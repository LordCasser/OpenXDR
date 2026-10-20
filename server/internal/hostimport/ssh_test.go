package hostimport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"openxdr/server/ent"
)

func TestSSHEnrollmentChecksFingerprintAndHostname(t *testing.T) {
	for _, tc := range []struct {
		name, hostname      string
		wrongKey, installed bool
	}{
		{"valid", "app-01", false, true}, {"wrong-host", "another-host", false, false}, {"wrong-key", "app-01", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			signer, _ := ssh.NewSignerFromKey(key)
			config := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
				if string(password) != "password-marker" {
					return nil, fmt.Errorf("invalid")
				}
				return nil, nil
			}}
			config.AddHostKey(signer)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			result := make(chan bool, 1)
			go func() {
				installed := false
				defer func() { result <- installed }()
				// 指纹不符时客户端会换主机密钥算法重新握手，握手失败的连接跳过、继续等下一条。
				var sc *ssh.ServerConn
				var channels <-chan ssh.NewChannel
				var requests <-chan *ssh.Request
				for sc == nil {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					if sc, channels, requests, err = ssh.NewServerConn(conn, config); err != nil {
						sc = nil
					}
				}
				defer sc.Close()
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					ch, requests, err := channel.Accept()
					if err != nil {
						return
					}
					for request := range requests {
						if request.Type != "exec" {
							request.Reply(false, nil)
							continue
						}
						var command struct{ Command string }
						if ssh.Unmarshal(request.Payload, &command) != nil {
							return
						}
						request.Reply(true, nil)
						if command.Command == "hostname" {
							io.WriteString(ch, "app-01\n")
						} else {
							input, _ := io.ReadAll(ch)
							installed = command.Command == "sh -s" && strings.Contains(string(input), "short-token") && strings.Contains(string(input), "echo fixed-installer") && !strings.Contains(command.Command, "short-token")
						}
						ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
						ch.Close()
						break
					}
				}
			}()
			host, portText, _ := net.SplitHostPort(listener.Addr().String())
			port, _ := strconv.Atoi(portText)
			c := &ent.HostCredential{Address: host, Port: port, Username: "root", Kind: "password"}
			fingerprint := ssh.FingerprintSHA256(signer.PublicKey())
			if tc.wrongKey {
				_, other, _ := ed25519.GenerateKey(rand.Reader)
				s, _ := ssh.NewSignerFromKey(other)
				fingerprint = ssh.FingerprintSHA256(s.PublicKey())
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = Install(ctx, c, Secret{Password: "password-marker"}, tc.hostname, "linux", "https://xdr.example.test", "short-token", "echo fixed-installer", fingerprint)
			listener.Close()
			if (err == nil) != tc.installed {
				t.Fatalf("结果不符: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "password-marker") {
				t.Fatal("SSH 错误泄露密码")
			}
			select {
			case got := <-result:
				if got != tc.installed {
					t.Fatal("指纹或主机名未通过仍执行安装，或安装未使用固定脚本")
				}
			case <-ctx.Done():
				t.Fatal("测试连接未结束")
			}
		})
	}
}
