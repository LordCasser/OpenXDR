package directory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func entraFixture(t *testing.T, handler http.HandlerFunc) *Entra {
	t.Helper()
	tenant := uuid.New()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-secret" || r.Method != "GET" {
			t.Error("认证或方法错误")
		}
		if r.URL.Path == "/v1.0/organization" {
			fmt.Fprintf(w, `{"value":[{"id":%q}]}`, tenant.String())
			return
		}
		handler(w, r)
	}))
	t.Cleanup(s.Close)
	e, err := NewEntra(uuid.New(), uuid.New(), tenant, s.URL, s.Client(), func(context.Context) (string, error) { return "test-secret", nil })
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEntraPagination(t *testing.T) {
	var e *Entra
	calls := 0
	id := uuid.New()
	e = entraFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch calls {
		case 1:
			if r.URL.Query().Get("$select") != "id,userPrincipalName,accountEnabled" || r.URL.Query().Get("$top") != "100" {
				t.Error("未选择所需字段")
			}
			fmt.Fprintf(w, `{"value":[{"id":%q,"userPrincipalName":"one@example.invalid","accountEnabled":false}],"@odata.nextLink":%q}`, strings.ToUpper(id.String()), e.root+"/v1.0/users?$skiptoken=a%2Bb%2F%3D")
		case 2:
			if r.URL.RawQuery != "$skiptoken=a%2Bb%2F%3D" {
				t.Error("分页令牌被重建")
			}
			fmt.Fprintf(w, `{"value":[],"@odata.nextLink":%q}`, e.root+"/v1.0/users?$skiptoken=last")
		case 3:
			fmt.Fprintf(w, `{"value":[{"id":%q,"userPrincipalName":"two@example.invalid"}]}`, uuid.New().String())
		default:
			t.Error("未停止分页")
		}
	})
	tokens := 0
	e.token = func(context.Context) (string, error) { tokens++; return "test-secret", nil }
	scan, err := e.ReadAccounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 || tokens != 1 || len(scan.Accounts) != 2 || scan.Accounts[0].ExternalID != id.String() || scan.Accounts[0].Enabled == nil || *scan.Accounts[0].Enabled || scan.Accounts[1].Enabled != nil {
		t.Fatal("分页或状态归一化错误")
	}
}

func TestEntraRejectsUntrustedNextLink(t *testing.T) {
	for _, suffix := range []string{"https://elsewhere.invalid/v1.0/users", "http://HOST/v1.0/users", "https://HOST/v1.0/groups", "https://HOST/v1.0/users#fragment", "https://user:password@HOST/v1.0/users", "/v1.0/users", "https://HOST/v1.0/%75sers", "https://HOST/v1.0/users?$select=id,userPrincipalName,accountEnabled&$top=100"} {
		t.Run(suffix, func(t *testing.T) {
			calls := 0
			e := entraFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				link := strings.ReplaceAll(suffix, "HOST", r.Host)
				fmt.Fprintf(w, `{"value":[],"@odata.nextLink":%q}`, link)
			})
			scan, err := e.ReadAccounts(context.Background())
			if err == nil || calls != 1 || len(scan.Accounts) != 0 {
				t.Fatal("越界或循环分页未拒绝")
			}
		})
	}
}

func TestEntraRejectsWrongTenant(t *testing.T) {
	e := entraFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("错误租户仍枚举账号") })
	e.tenant = uuid.New()
	if _, err := e.ReadAccounts(context.Background()); err == nil {
		t.Fatal("租户错配未拒绝")
	}
}

func TestEntraMalformedAndHTTPFailures(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `{"value":null}`, `{"value":[]} {}`, `{"value":[{"id":"bad","userPrincipalName":"u"}]}`, `{"value":[{"id":"00000000-0000-0000-0000-000000000000","userPrincipalName":"u"}]}`, strings.Repeat(" ", maxPageBytes+1)} {
		e := entraFixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
		if _, err := e.ReadAccounts(context.Background()); err == nil {
			t.Fatalf("接受坏响应，长度 %d", len(body))
		}
	}
	for _, status := range []int{302, 401, 403, 429, 500} {
		calls := 0
		e := entraFixture(t, func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.Header().Set("Location", "/v1.0/users")
			w.WriteHeader(status)
			fmt.Fprint(w, "test-secret")
		})
		_, err := e.ReadAccounts(context.Background())
		if err == nil || strings.Contains(err.Error(), "test-secret") || calls != 1 {
			t.Fatal("错误泄密或跳转")
		}
	}
}

func TestEntraDuplicateAndCapacity(t *testing.T) {
	for _, duplicate := range []bool{true, false} {
		var e *Entra
		calls := 0
		id := uuid.New().String()
		e = entraFixture(t, func(w http.ResponseWriter, r *http.Request) {
			calls++
			users := make([]map[string]any, 100)
			for i := range users {
				value := uuid.New().String()
				if duplicate {
					value = id
				}
				users[i] = map[string]any{"id": value, "userPrincipalName": "u"}
			}
			json.NewEncoder(w).Encode(map[string]any{"value": users, "@odata.nextLink": fmt.Sprintf("%s/v1.0/users?$skiptoken=%d", e.root, calls)})
		})
		scan, err := e.ReadAccounts(context.Background())
		if err == nil || len(scan.Accounts) != 0 {
			t.Fatal("重复或超限未拒绝")
		}
		if !duplicate && calls != 101 {
			t.Fatalf("上限请求次数 %d", calls)
		}
	}
}

func TestEntraConfigAndCancellation(t *testing.T) {
	for _, root := range []string{"http://graph.microsoft.com", "https://u:p@host", "https://host/v1.0", "https://host?", "https://host#secret"} {
		if _, err := NewEntra(uuid.New(), uuid.New(), uuid.New(), root, nil, func(context.Context) (string, error) { return "token", nil }); err == nil {
			t.Fatal("无效配置获准")
		}
	}
	e := entraFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("取消后仍访问账号") })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.ReadAccounts(ctx); err == nil {
		t.Fatal("取消仍成功")
	}
}
