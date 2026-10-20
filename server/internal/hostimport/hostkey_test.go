package hostimport

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

// 主机同时有 ECDSA 与 ed25519 密钥时，操作者核对哪一把都能连上，且指纹不符的握手不会走到认证。
func TestConnectVerifiedTriesHostKeyAlgorithms(t *testing.T) {
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	edSigner, _ := ssh.NewSignerFromKey(edKey)
	ecSigner, _ := ssh.NewSignerFromKey(ecKey)
	var auths atomic.Int32
	config := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
		auths.Add(1)
		return nil, nil
	}}
	config.AddHostKey(ecSigner)
	config.AddHostKey(edSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if sc, chans, reqs, err := ssh.NewServerConn(conn, config); err == nil {
					go ssh.DiscardRequests(reqs)
					go func() {
						for range chans {
						}
					}()
					_ = sc.Wait()
				}
			}()
		}
	}()
	for _, signer := range []ssh.Signer{edSigner, ecSigner} {
		auths.Store(0)
		client, err := connectVerified(context.Background(), listener.Addr().String(), "ops", ssh.Password("x"), ssh.FingerprintSHA256(signer.PublicKey()))
		if err != nil {
			t.Fatalf("%s: %v", signer.PublicKey().Type(), err)
		}
		client.Close()
		if auths.Load() != 1 {
			t.Fatalf("%s: 认证 %d 次", signer.PublicKey().Type(), auths.Load())
		}
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(other)
	auths.Store(0)
	if _, err := connectVerified(context.Background(), listener.Addr().String(), "ops", ssh.Password("x"), ssh.FingerprintSHA256(otherSigner.PublicKey())); err == nil || auths.Load() != 0 {
		t.Fatal("错误指纹被接受或已提交凭据", err, auths.Load())
	}
}
