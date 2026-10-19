package directory

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

func TestOAuthCacheAndRotation(t *testing.T) {
	var calls atomic.Int32
	var secret atomic.Value
	secret.Store("first+&= secret")
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Method != "POST" || r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != "client" || r.Form.Get("client_secret") != secret.Load().(string) || r.Form.Get("scope") != "resource/.default" {
			t.Error("OAuth 表单错误")
		}
		fmt.Fprintf(w, `{"access_token":"token-%d","token_type":"Bearer","expires_in":3600}`, calls.Load())
	}))
	defer s.Close()
	provider, err := NewClientCredentials(OAuthConfig{TokenURL: s.URL, ClientID: "client", Scope: "resource/.default"}, func() string { return secret.Load().(string) }, s.Client())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := provider(context.Background())
			if err != nil || token != "token-1" {
				t.Errorf("并发取令牌失败: %v", err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("重复换取令牌")
	}
	secret.Store("rotated")
	if token, err := provider(context.Background()); err != nil || token != "token-2" || calls.Load() != 2 {
		t.Fatal("密钥变化未刷新")
	}
	secret.Store("")
	if token, err := provider(context.Background()); err == nil || token != "" {
		t.Fatal("缺失密钥仍复用缓存")
	}
}

func TestOAuthShortExpiryAndErrors(t *testing.T) {
	for _, body := range []string{`{"access_token":"token","token_type":"Bearer","expires_in":1}`, `{}`, `{"access_token":"token","token_type":"Bearer","expires_in":0}`, `{"access_token":"token","token_type":"MAC","expires_in":300}`, `{"access_token":"bad token","token_type":"Bearer","expires_in":300}`, strings.Repeat(" ", 128<<10+1)} {
		calls := 0
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; fmt.Fprint(w, body) }))
		provider, err := NewClientCredentials(OAuthConfig{TokenURL: s.URL, ClientID: "client"}, func() string { return "secret" }, s.Client())
		if err != nil {
			t.Fatal(err)
		}
		token, err := provider(context.Background())
		if strings.Contains(body, `"expires_in":1`) {
			if err != nil || token != "token" {
				t.Fatal("短期令牌读取失败")
			}
			if _, err := provider(context.Background()); err != nil || calls != 2 {
				t.Fatal("短期令牌被复用")
			}
		} else if err == nil || token != "" {
			t.Fatal("无效响应获准")
		}
		s.Close()
	}
	for _, status := range []int{302, 400, 401, 429, 500} {
		calls := 0
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.Header().Set("Location", "/other")
			w.WriteHeader(status)
			fmt.Fprint(w, "secret-response")
		}))
		provider, err := NewClientCredentials(OAuthConfig{TokenURL: s.URL, ClientID: "client"}, func() string { return "secret" }, s.Client())
		if err != nil {
			t.Fatal(err)
		}
		_, err = provider(context.Background())
		if err == nil || strings.Contains(err.Error(), "secret") || calls != 1 {
			t.Fatal("OAuth 错误泄密或重定向")
		}
		s.Close()
	}
}

func TestOAuthConfiguration(t *testing.T) {
	for _, endpoint := range []string{"http://host/token", "https://user:secret@host/token", "https://host/token?secret=x", "https://host/token#secret"} {
		if _, err := NewClientCredentials(OAuthConfig{TokenURL: endpoint, ClientID: "client"}, func() string { return "secret" }, nil); err == nil {
			t.Fatal("不安全端点获准")
		}
	}
	config := sourceConfig{ID: uuid.New(), GroupID: uuid.New(), Kind: "entra", URL: "https://graph.microsoft.com", TenantID: uuid.New(), OAuth: &OAuthConfig{TokenURL: "https://login.example.invalid/token", ClientID: "client", ClientSecretEnv: "CLIENT_SECRET", Scope: "https://graph.microsoft.com/.default"}}
	data, _ := json.Marshal([]sourceConfig{config})
	jobs, err := LoadConfig(string(data), func(string) string { return "secret" })
	if err != nil || len(jobs) != 1 {
		t.Fatalf("OAuth 来源配置失败: %v", err)
	}
	config.TokenEnv = "TOKEN"
	data, _ = json.Marshal([]sourceConfig{config})
	if _, err := LoadConfig(string(data), func(string) string { return "secret" }); err == nil {
		t.Fatal("双认证模式获准")
	}
}

func TestOAuthCanceledWaiter(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		fmt.Fprint(w, `{"access_token":"token","token_type":"Bearer","expires_in":300}`)
	}))
	defer s.Close()
	provider, err := NewClientCredentials(OAuthConfig{TokenURL: s.URL, ClientID: "client"}, func() string { return "secret" }, s.Client())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := provider(context.Background()); done <- err }()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, waitErr := provider(ctx)
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if waitErr == nil {
		t.Fatal("取消等待未生效")
	}
}

func TestOAuthConfiguredKeycloakRead(t *testing.T) {
	tokens, pages := 0, 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			tokens++
			if err := r.ParseForm(); err != nil || r.Form.Get("client_secret") != "test-secret" {
				t.Error("客户端密钥未正确传递")
			}
			fmt.Fprint(w, `{"access_token":"directory-token","token_type":"Bearer","expires_in":300}`)
			return
		}
		if r.URL.Path == "/admin/realms/company/users/count" {
			fmt.Fprint(w, "1")
			return
		}
		if r.URL.Path != "/admin/realms/company/users" || r.Header.Get("Authorization") != "Bearer directory-token" {
			t.Error("目录认证或路径错误")
		}
		pages++
		if r.URL.Query().Get("first") == "0" {
			fmt.Fprint(w, `[{"id":"one","username":"account","enabled":true}]`)
		} else {
			fmt.Fprint(w, `[]`)
		}
	}))
	defer s.Close()
	root := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}))
	config := sourceConfig{ID: uuid.New(), GroupID: uuid.New(), Kind: "keycloak", URL: s.URL, Realm: "company", CAEnv: "CA", OAuth: &OAuthConfig{TokenURL: s.URL + "/token", ClientID: "client", ClientSecretEnv: "CLIENT_SECRET"}}
	data, _ := json.Marshal([]sourceConfig{config})
	jobs, err := LoadConfig(string(data), func(key string) string {
		if key == "CA" {
			return root
		}
		if key == "CLIENT_SECRET" {
			return "test-secret"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	scan, err := jobs[0].Reader.ReadAccounts(context.Background())
	if err != nil || len(scan.Accounts) != 1 || tokens != 1 || pages != 2 || scan.Source != jobs[0].Source {
		t.Fatalf("配置到目录读取失败: %v", err)
	}
}
