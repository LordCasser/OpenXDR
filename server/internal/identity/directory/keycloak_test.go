package directory

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func keycloakFixture(t *testing.T, handler http.HandlerFunc) *Keycloak {
	t.Helper()
	s := httptest.NewTLSServer(handler)
	t.Cleanup(s.Close)
	k, err := NewKeycloak(uuid.New(), uuid.New(), s.URL+"/auth", "company", s.Client(), func(context.Context) (string, error) { return "private-token", nil })
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKeycloakPaginationAndUnknownState(t *testing.T) {
	requests := 0
	k := keycloakFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/admin/realms/company/users/count" {
			fmt.Fprint(w, "3")
			return
		}
		requests++
		if r.Method != "GET" || r.URL.Path != "/auth/admin/realms/company/users" || r.Header.Get("Authorization") != "Bearer private-token" || r.URL.Query().Get("max") != "100" {
			t.Error("请求契约错误")
		}
		switch r.URL.Query().Get("first") {
		case "0":
			fmt.Fprint(w, `[{"id":"one","username":"same","enabled":true},{"id":"two","username":"same","enabled":false}]`)
		case "2":
			fmt.Fprint(w, `[{"id":"three","username":"other"}]`)
		case "3":
			fmt.Fprint(w, `[]`)
		default:
			t.Error("偏移错误")
			http.Error(w, "bad", 400)
		}
	})
	scan, err := k.ReadAccounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if requests != 3 || len(scan.Accounts) != 3 || scan.Accounts[2].Enabled != nil || !*scan.Accounts[0].Enabled || *scan.Accounts[1].Enabled || scan.FinishedAt.Before(scan.StartedAt) {
		t.Fatalf("分页或状态丢失: %+v", scan)
	}
}

func TestKeycloakFailureDiscardsPartialResults(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `[] []`, `[{"username":"missing-id"}]`, `[{"id":"one","username":"duplicate"}]`, `[{"id":"two","username":"bad","enabled":"false"}]`, strings.Repeat(" ", maxPageBytes+1)} {
		t.Run(fmt.Sprintf("body-%d", len(body)), func(t *testing.T) {
			k := keycloakFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/count") {
					fmt.Fprint(w, "1")
					return
				}
				if r.URL.Query().Get("first") == "0" {
					fmt.Fprint(w, `[{"id":"one","username":"ok"}]`)
					return
				}
				fmt.Fprint(w, body)
			})
			scan, err := k.ReadAccounts(context.Background())
			if err == nil || len(scan.Accounts) != 0 || scan.Source.ID != uuid.Nil {
				t.Fatal("失败时泄露部分成功结果")
			}
		})
	}
	for _, status := range []int{301, 401, 403, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			k := keycloakFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(status)
				fmt.Fprint(w, "private-token")
			})
			_, err := k.ReadAccounts(context.Background())
			if err == nil || strings.Contains(err.Error(), "private-token") || calls != 1 {
				t.Fatal("错误泄密或跟随跳转")
			}
		})
	}
}

func TestKeycloakBoundsAndCancellation(t *testing.T) {
	calls := 0
	k := keycloakFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/count") {
			fmt.Fprint(w, "5000")
			return
		}
		calls++
		fmt.Fprint(w, "[")
		for i := 0; i < 100; i++ {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			fmt.Fprintf(w, `{"id":"%d-%d","username":"u"}`, calls, i)
		}
		fmt.Fprint(w, "]")
	})
	if scan, err := k.ReadAccounts(context.Background()); err == nil || len(scan.Accounts) > 0 || calls != 101 {
		t.Fatal("账号容量没有拒绝")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := k.ReadAccounts(ctx); err == nil {
		t.Fatal("取消请求仍成功")
	}
}

func TestKeycloakConfigurationAndTokenErrors(t *testing.T) {
	provider := func(context.Context) (string, error) { return "token", nil }
	for _, base := range []string{"http://host", "https://u:p@host", "https://host?token=secret", "https://host#fragment", "https:///missing"} {
		if _, err := NewKeycloak(uuid.New(), uuid.New(), base, "realm", nil, provider); err == nil {
			t.Fatalf("接受无效配置 %s", base)
		}
	}
	k := keycloakFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("无有效令牌仍发送请求") })
	k.token = func(context.Context) (string, error) { return "", fmt.Errorf("private-token") }
	if _, err := k.ReadAccounts(context.Background()); err == nil || strings.Contains(err.Error(), "private-token") {
		t.Fatal("令牌错误泄密")
	}
	k.token = func(context.Context) (string, error) { return "bad\r\ntoken", nil }
	if _, err := k.ReadAccounts(context.Background()); err == nil {
		t.Fatal("接受无效令牌")
	}
}

func TestAccountIdentityNamespaces(t *testing.T) {
	source := Source{ID: uuid.New(), GroupID: uuid.New(), Kind: "keycloak", Authority: "https://host/realms/one"}
	id, err := source.AccountID("stable-id")
	if err != nil {
		t.Fatal(err)
	}
	again, _ := source.AccountID("stable-id")
	if id != again {
		t.Fatal("身份不稳定")
	}
	for _, mutate := range []func(*Source){func(s *Source) { s.ID = uuid.New() }, func(s *Source) { s.GroupID = uuid.New() }, func(s *Source) { s.Authority = "https://host/realms/two" }, func(s *Source) { s.Kind = "ldap" }} {
		other := source
		mutate(&other)
		got, err := other.AccountID("stable-id")
		if err != nil || got == id {
			t.Fatal("不同来源身份被合并")
		}
	}
	if _, err := source.AccountID(""); err == nil {
		t.Fatal("空稳定标识获准")
	}
	source.GroupID = uuid.Nil
	if _, err := source.AccountID("stable-id"); err == nil {
		t.Fatal("无归组来源获准")
	}
}

// 偏移分页遇上扫描期间的增删：错位出重复或漏掉账号时整轮重扫，取得一致快照才返回；一直在变就拒绝
func TestKeycloakConsistentSnapshot(t *testing.T) {
	type round struct {
		count int
		pages []string
	}
	serve := func(rounds []round) (*Keycloak, *int) {
		scans := 0
		var cur round
		counts := 0
		k := keycloakFixture(t, func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/count") {
				// 每轮扫描前后各查一次总数：奇数次开始一轮
				if counts%2 == 0 && scans < len(rounds) {
					cur = rounds[scans]
					scans++
				}
				counts++
				fmt.Fprint(w, cur.count)
				return
			}
			first := r.URL.Query().Get("first")
			i := map[string]int{"0": 0, "1": 1, "2": 2, "3": 3}[first]
			if i < len(cur.pages) {
				fmt.Fprint(w, cur.pages[i])
			} else {
				fmt.Fprint(w, "[]")
			}
		})
		return k, &scans
	}
	ok := []string{`[{"id":"a","username":"a"}]`, `[{"id":"b","username":"b"}]`}
	// 第一轮：第二页错位又给了 a；第二轮正常
	k, scans := serve([]round{{2, []string{`[{"id":"a","username":"a"}]`, `[{"id":"a","username":"a"}]`}}, {2, ok}})
	if scan, err := k.ReadAccounts(context.Background()); err != nil || len(scan.Accounts) != 2 || *scans != 2 {
		t.Fatalf("错位后应重扫取得一致快照: %v %d", err, *scans)
	}
	// 漏掉账号：扫到 1 个、总数是 2，重扫
	k, scans = serve([]round{{2, ok[:1]}, {2, ok}})
	if scan, err := k.ReadAccounts(context.Background()); err != nil || len(scan.Accounts) != 2 || *scans != 2 {
		t.Fatalf("漏掉账号应重扫: %v %d", err, *scans)
	}
	// 一直对不上：三轮后拒绝，不给部分结果
	bad := round{3, ok}
	k, scans = serve([]round{bad, bad, bad, {2, ok}})
	if scan, err := k.ReadAccounts(context.Background()); err == nil || len(scan.Accounts) != 0 || *scans != 3 || !strings.Contains(err.Error(), "一致快照") {
		t.Fatalf("持续不一致应在三轮后拒绝: %v %d", err, *scans)
	}
}
