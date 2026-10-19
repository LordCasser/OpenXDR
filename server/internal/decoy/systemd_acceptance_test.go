//go:build linux && systemdacceptance

package decoy

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

// 只在一次性 systemd 容器中显式运行：真实安装脚本和服务，平台为 TLS 测试替身。
func TestSystemdCredentialAcceptance(t *testing.T) {
	if os.Getenv("DECOY_SYSTEMD_ACCEPTANCE") != "1" {
		t.Skip("需要显式启用隔离容器验收")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil || os.Geteuid() != 0 {
		t.Fatal("仅允许一次性 root Docker 容器")
	}
	propagation, err := exec.Command("findmnt", "--noheadings", "--target", "/run", "-o", "PROPAGATION").Output()
	if err != nil || !strings.Contains(string(propagation), "shared") {
		t.Fatal("验收容器的 /run 必须支持 shared 挂载传播，否则 systemd 252 无法交付凭据")
	}
	dir := os.Getenv("DECOY_TEST_DIST_DIR")
	if dir == "" {
		t.Fatal("缺少测试安装包目录")
	}
	for _, kind := range []string{"http", "ssh", "file"} {
		t.Run(kind, func(t *testing.T) {
			id := uuid.NewString()
			token := strings.Repeat("a", 64)
			profile, _ := Lookup(kind, "decoy")
			m := Manifest{ID: id, AssetID: uuid.NewString(), GroupID: uuid.NewString(), Kind: kind, Profile: "decoy", Template: profile.Template, Marker: strings.Repeat("b", 64), Resource: "README.md"}
			if kind != "file" {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				m.Port = l.Addr().(*net.TCPAddr).Port
				l.Close()
				m.Resource = ""
			}
			var mu sync.Mutex
			state := ""
			events := map[string]bool{}
			platform := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer "+token {
					w.WriteHeader(401)
					return
				}
				switch r.URL.Path {
				case "/api/decoy-runtime/" + id + "/config":
					json.NewEncoder(w).Encode(m)
				case "/api/decoy-runtime/" + id + "/lease":
					var body struct {
						State string `json:"state"`
					}
					if json.NewDecoder(r.Body).Decode(&body) != nil {
						w.WriteHeader(400)
						return
					}
					mu.Lock()
					state = body.State
					mu.Unlock()
					w.WriteHeader(204)
				case "/api/decoy-runtime/" + id + "/events":
					var body Observation
					if json.NewDecoder(r.Body).Decode(&body) != nil {
						w.WriteHeader(400)
						return
					}
					mu.Lock()
					events[body.Kind] = true
					mu.Unlock()
					w.WriteHeader(204)
				default:
					w.WriteHeader(404)
				}
			}))
			defer platform.Close()
			caPath := "/etc/ssl/certs/ca-certificates.crt"
			old, err := os.ReadFile(caPath)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(caPath, append(append([]byte{}, old...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: platform.Certificate().Raw})...), 0644); err != nil {
				t.Fatal(err)
			}
			defer os.WriteFile(caPath, old, 0644)
			fileRoot := ""
			if kind == "file" {
				fileRoot = "/srv/decoy-acceptance-" + id
				if err = os.Mkdir(fileRoot, 0755); err != nil {
					t.Fatal(err)
				}
			}
			script, err := InstallScript(dir, "amd64", platform.URL, id, kind, "127.0.0.1", fileRoot)
			if err != nil {
				t.Fatal(err)
			}
			unit := "aidr-decoy-" + id + ".service"
			defer exec.Command("systemctl", "disable", "--now", unit).Run()
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			install := exec.CommandContext(ctx, "sh", "-s")
			install.Stdin = strings.NewReader("set -- '" + platform.URL + "' '" + token + "'\n" + script)
			if out, err := install.CombinedOutput(); err != nil {
				t.Fatalf("安装失败: %v %s", err, out)
			}
			wait := func(check func() bool) {
				t.Helper()
				deadline := time.Now().Add(15 * time.Second)
				for time.Now().Before(deadline) {
					mu.Lock()
					ok := check()
					mu.Unlock()
					if ok {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
				out, _ := exec.Command("journalctl", "-u", unit, "--no-pager", "-n", "15").CombinedOutput()
				t.Fatalf("运行条件超时: %s", out)
			}
			wait(func() bool { return state == "running" })
			if err := exec.Command("systemctl", "is-active", "--quiet", unit).Run(); err != nil {
				t.Fatal("服务未保持 active")
			}
			event := ""
			switch kind {
			case "http":
				client := &http.Client{Timeout: 3 * time.Second}
				res, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/decoy/%s", m.Port, id))
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
				if res.StatusCode != 200 {
					t.Fatal(res.StatusCode)
				}
				event = "http_page"
			case "ssh":
				connection, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", m.Port), &ssh.ClientConfig{User: "acceptance", Auth: []ssh.AuthMethod{ssh.Password("synthetic-test")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 3 * time.Second})
				if err == nil {
					connection.Close()
					t.Fatal("诱饵不应允许登录")
				}
				event = "ssh_authentication_attempt"
			case "file":
				if _, err := os.ReadFile(filepath.Join(fileRoot, "archive-"+id, "README.md")); err != nil {
					t.Fatal(err)
				}
				event = "file_opened"
			}
			wait(func() bool { return events[event] })
			if out, err := exec.Command("systemctl", "stop", unit).CombinedOutput(); err != nil {
				t.Fatalf("停止: %v %s", err, out)
			}
			wait(func() bool { return state == "stopped" })
			if kind == "file" {
				if _, err := os.Stat(filepath.Join(fileRoot, "archive-"+id)); !os.IsNotExist(err) {
					t.Fatal("诱饵文件未清理")
				}
			}
		})
	}
}
