package directory

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

const (
	akAlice   = "0f8fad5b-d9cb-469f-a165-70867728950e"
	akBob     = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
	akOutpost = "1b4e28ba-2fa1-41d2-883f-0016d3cca427"
	akRobot   = "6fa459ea-ee8a-4ca4-894e-db77e160355e"
)

func akUser(id, name, kind string, active bool) string {
	return fmt.Sprintf(`{"pk":%d,"uuid":%q,"username":%q,"name":"N","email":"x@example.invalid","is_active":%t,"type":%q}`, len(name), id, name, active, kind)
}

func akPage(current, next, count int, users ...string) string {
	return fmt.Sprintf(`{"pagination":{"next":%d,"previous":0,"count":%d,"current":%d,"total_pages":2,"start_index":1,"end_index":2},"results":[%s]}`, next, count, current, strings.Join(users, ","))
}

// authentikServer 按页码返回固定页；page_size=1 的请求是取总数，返回 counts 里的下一个值（用完后保持最后一个）
func authentikServer(t *testing.T, counts []int, pages map[int]string) (*httptest.Server, *int) {
	t.Helper()
	countCalls := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v3/core/users/" || r.Header.Get("Authorization") != "Bearer private-token" {
			t.Errorf("请求契约错误: %s %s", r.Method, r.URL.Path)
			http.Error(w, "bad", 400)
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		count := counts[min(countCalls, len(counts)-1)]
		if r.URL.Query().Get("page_size") == "1" {
			countCalls++
			fmt.Fprint(w, akPage(1, 0, count))
			return
		}
		if r.URL.Query().Get("page_size") != "100" {
			t.Error("分页大小错误")
		}
		body, ok := pages[page]
		if !ok {
			http.Error(w, `{"detail":"Invalid page."}`, 404)
			return
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(s.Close)
	return s, &countCalls
}

func authentikFixture(t *testing.T, s *httptest.Server, services bool) *Authentik {
	t.Helper()
	a, err := NewAuthentik(uuid.New(), uuid.New(), s.URL+"/", services, s.Client(), func(context.Context) (string, error) { return "private-token", nil })
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAuthentikPaginationAndServiceAccounts(t *testing.T) {
	pages := map[int]string{
		1: akPage(1, 2, 4, akUser(strings.ToUpper(akAlice), "alice", "internal", true), akUser(akOutpost, "ak-outpost-1", "internal_service_account", true)),
		2: akPage(2, 0, 4, akUser(akBob, "bob", "external", false), akUser(akRobot, "robot", "service_account", true)),
	}
	s, _ := authentikServer(t, []int{4}, pages)
	a := authentikFixture(t, s, false)
	if a.source.Kind != "authentik" || a.source.Authority != s.URL {
		t.Fatalf("来源错误: %+v", a.source)
	}
	scan, err := a.ReadAccounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// 默认只保留人类用户；uuid 规范成小写，username 只作名称
	if len(scan.Accounts) != 2 || scan.Accounts[0].ExternalID != akAlice || scan.Accounts[0].Username != "alice" || !*scan.Accounts[0].Enabled ||
		scan.Accounts[1].ExternalID != akBob || *scan.Accounts[1].Enabled || scan.Source != a.source || scan.FinishedAt.Before(scan.StartedAt) {
		t.Fatalf("分页、过滤或状态错误: %+v", scan)
	}
	scan, err = authentikFixture(t, s, true).ReadAccounts(context.Background())
	if err != nil || len(scan.Accounts) != 4 || scan.Accounts[1].ExternalID != akOutpost || scan.Accounts[3].ExternalID != akRobot {
		t.Fatalf("包含服务账号时丢失账号: %v %+v", err, scan)
	}
	// is_active 缺省保留未知
	s, _ = authentikServer(t, []int{1}, map[int]string{1: akPage(1, 0, 1, `{"uuid":"`+akAlice+`","username":"alice","type":"internal"}`)})
	scan, err = authentikFixture(t, s, false).ReadAccounts(context.Background())
	if err != nil || len(scan.Accounts) != 1 || scan.Accounts[0].Enabled != nil {
		t.Fatalf("未知状态被补齐: %v %+v", err, scan)
	}
}

// 页码分页遇上扫描期间增删：前后总数不一致、重复或漏掉都整轮重扫，三轮仍不一致就拒绝，不给部分结果
func TestAuthentikConsistentSnapshot(t *testing.T) {
	alice, bob := akUser(akAlice, "alice", "internal", true), akUser(akBob, "bob", "internal", true)
	good := map[int]string{1: akPage(1, 2, 2, alice), 2: akPage(2, 0, 2, bob)}
	for name, test := range map[string]struct {
		counts []int
		pages  map[int]string
	}{
		"前后总数不一致": {[]int{2, 3}, good},
		"重复账号":    {[]int{2}, map[int]string{1: akPage(1, 2, 2, alice), 2: akPage(2, 0, 2, alice)}},
		"漏掉账号":    {[]int{2}, map[int]string{1: akPage(1, 0, 2, alice)}},
		"页内总数变化":  {[]int{2}, map[int]string{1: akPage(1, 2, 2, alice), 2: akPage(2, 0, 3, bob)}},
	} {
		t.Run(name, func(t *testing.T) {
			s, countCalls := authentikServer(t, test.counts, test.pages)
			scan, err := authentikFixture(t, s, true).ReadAccounts(context.Background())
			if !errors.Is(err, errAuthentikInconsistent) || !strings.Contains(err.Error(), "一致快照") || len(scan.Accounts) != 0 || scan.Source.ID != uuid.Nil {
				t.Fatalf("不一致快照未拒绝: %v %+v", err, scan)
			}
			if *countCalls < consistentAttempts {
				t.Fatalf("未重扫: %d", *countCalls)
			}
		})
	}
	// 第一轮总数变化，第二轮稳定：重扫后成功
	s, _ := authentikServer(t, []int{2, 3, 2}, good)
	if scan, err := authentikFixture(t, s, true).ReadAccounts(context.Background()); err != nil || len(scan.Accounts) != 2 {
		t.Fatalf("稳定后应取得一致快照: %v", err)
	}
}

func TestAuthentikFailureDiscardsPartialResults(t *testing.T) {
	alice := akUser(akAlice, "alice", "internal", true)
	for _, body := range []string{
		`null`, `{}`, `[]`, `{"pagination":{"next":0,"current":2,"count":2},"results":[]}`,
		`{"pagination":{"next":0,"current":2,"count":2}}`,
		akPage(2, 0, 2, `{"uuid":"not-a-uuid","username":"bob","type":"internal"}`),
		akPage(2, 0, 2, `{"pk":2,"username":"bob","type":"internal"}`),
		akPage(2, 0, 2, `{"uuid":"`+akBob+`","username":"","type":"internal"}`),
		akPage(2, 0, 2, `{"uuid":"`+akBob+`","username":"bob","type":"robot"}`),
		akPage(2, 0, 2, `{"uuid":"`+akBob+`","username":"bob"}`),
		akPage(2, 0, 2, `{"uuid":"`+akBob+`","username":"bob","type":"internal","is_active":"false"}`),
		akPage(2, 5, 2, akUser(akBob, "bob", "internal", true)),
		strings.Repeat(" ", maxPageBytes+1),
	} {
		t.Run(fmt.Sprintf("body-%d", len(body)), func(t *testing.T) {
			s, _ := authentikServer(t, []int{2}, map[int]string{1: akPage(1, 2, 2, alice), 2: body})
			scan, err := authentikFixture(t, s, true).ReadAccounts(context.Background())
			if err == nil || len(scan.Accounts) != 0 || scan.Source.ID != uuid.Nil {
				t.Fatal("失败时泄露部分成功结果")
			}
		})
	}
	// 超过分页大小
	users := make([]string, 101)
	for i := range users {
		users[i] = akUser(uuid.NewString(), "u"+strconv.Itoa(i), "internal", true)
	}
	s, _ := authentikServer(t, []int{101}, map[int]string{1: akPage(1, 0, 101, users...)})
	if _, err := authentikFixture(t, s, true).ReadAccounts(context.Background()); err == nil {
		t.Fatal("超大分页获准")
	}
	// 总数超过上限，不开始枚举
	s, _ = authentikServer(t, []int{10001}, map[int]string{})
	if _, err := authentikFixture(t, s, true).ReadAccounts(context.Background()); err == nil {
		t.Fatal("账号容量没有拒绝")
	}
}

func TestAuthentikTokenAndHTTPErrors(t *testing.T) {
	for _, status := range []int{301, 401, 403, 404, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(status)
				fmt.Fprint(w, "private-token")
			}))
			defer s.Close()
			_, err := authentikFixture(t, s, false).ReadAccounts(context.Background())
			if err == nil || strings.Contains(err.Error(), "private-token") || calls != 1 {
				t.Fatal("错误泄密或跟随跳转")
			}
		})
	}
	s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("无有效令牌仍发送请求") }))
	defer s.Close()
	a := authentikFixture(t, s, false)
	for _, provider := range []TokenProvider{
		func(context.Context) (string, error) { return "", fmt.Errorf("private-token") },
		func(context.Context) (string, error) { return "", nil },
		func(context.Context) (string, error) { return "bad\r\ntoken", nil },
		func(context.Context) (string, error) { return " padded", nil },
	} {
		a.token = provider
		if _, err := a.ReadAccounts(context.Background()); err == nil || strings.Contains(err.Error(), "private-token") {
			t.Fatal("令牌错误获准或泄密")
		}
	}
	for _, base := range []string{"http://host", "https://u:p@host", "https://host?token=secret", "https://host?", "https://host#fragment", "https:///missing", "://"} {
		if _, err := NewAuthentik(uuid.New(), uuid.New(), base, false, nil, a.token); err == nil {
			t.Fatalf("接受无效配置 %s", base)
		}
	}
	if _, err := NewAuthentik(uuid.New(), uuid.New(), "https://host", false, nil, nil); err == nil {
		t.Fatal("缺少令牌提供器获准")
	}
}

func TestAuthentikTLSVerification(t *testing.T) {
	calls := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer s.Close()
	// 不信任自签证书的默认客户端必须握手失败，不发出带令牌的请求
	a, err := NewAuthentik(uuid.New(), uuid.New(), s.URL, false, nil, func(context.Context) (string, error) { return "private-token", nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.ReadAccounts(context.Background()); err == nil || calls != 0 {
		t.Fatal("证书校验失败仍读取目录")
	}
	// 启动配置不带 caEnv 时同样不信任自签证书
	data, _ := json.Marshal([]sourceConfig{{ID: uuid.New(), GroupID: uuid.New(), Kind: "authentik", URL: s.URL, TokenEnv: "AUTHENTIK_TOKEN"}})
	jobs, err := LoadConfig(string(data), func(string) string { return "private-token" })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jobs[0].Reader.ReadAccounts(context.Background()); err == nil || calls != 0 {
		t.Fatal("配置路径跳过证书校验")
	}
}

func TestAuthentikTimeoutAndCancellation(t *testing.T) {
	release := make(chan struct{})
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer s.Close()
	defer close(release)
	client := s.Client()
	client.Timeout = 50 * time.Millisecond
	a, err := NewAuthentik(uuid.New(), uuid.New(), s.URL, false, client, func(context.Context) (string, error) { return "private-token", nil })
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := a.ReadAccounts(context.Background()); err == nil || time.Since(started) > 5*time.Second {
		t.Fatal("单次请求超时未生效")
	}
	// 整轮期限：调用方给的期限早于内部两分钟时以调用方为准
	a.client.Timeout = 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started = time.Now()
	if _, err := a.ReadAccounts(ctx); err == nil || time.Since(started) > 5*time.Second {
		t.Fatal("整轮期限未生效")
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if _, err := a.ReadAccounts(ctx); err == nil {
		t.Fatal("取消请求仍成功")
	}
}

func TestAuthentikConfig(t *testing.T) {
	s, _ := authentikServer(t, []int{2}, map[int]string{1: akPage(1, 0, 2, akUser(akAlice, "alice", "internal", true), akUser(akRobot, "robot", "service_account", true))})
	root := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}))
	getenv := func(key string) string {
		return map[string]string{"AUTHENTIK_CA": root, "AUTHENTIK_TOKEN": "private-token"}[key]
	}
	base := sourceConfig{ID: uuid.New(), GroupID: uuid.New(), Kind: "authentik", URL: s.URL, TokenEnv: "AUTHENTIK_TOKEN", CAEnv: "AUTHENTIK_CA"}
	for _, services := range []bool{false, true} {
		config := base
		config.IncludeServiceAccounts = services
		data, _ := json.Marshal([]sourceConfig{config})
		jobs, err := LoadConfig(string(data), getenv)
		if err != nil || len(jobs) != 1 || jobs[0].Source.Kind != "authentik" || jobs[0].Source.Authority != s.URL || jobs[0].Interval != 15*time.Minute {
			t.Fatalf("配置加载失败: %v", err)
		}
		scan, err := jobs[0].Reader.ReadAccounts(context.Background())
		want := map[bool]int{false: 1, true: 2}[services]
		if err != nil || len(scan.Accounts) != want || scan.Source != jobs[0].Source {
			t.Fatalf("配置到目录读取失败: %v %+v", err, scan)
		}
	}
	for _, mutate := range []func(*sourceConfig){
		func(c *sourceConfig) { c.URL = "http://authentik.invalid" },
		func(c *sourceConfig) { c.TokenEnv = "" },
		func(c *sourceConfig) { c.TokenEnv = "MISSING_TOKEN" },
		func(c *sourceConfig) { c.TokenEnv = "private-token" },
		func(c *sourceConfig) { c.Realm = "one" },
		func(c *sourceConfig) { c.TenantID = uuid.New() },
		func(c *sourceConfig) { c.BaseDN = "dc=example" },
		func(c *sourceConfig) { c.BindUserEnv = "USER" },
		func(c *sourceConfig) {
			c.TokenEnv = ""
			c.OAuth = &OAuthConfig{TokenURL: "https://authentik.invalid/application/o/token/", ClientID: "c", ClientSecretEnv: "AUTHENTIK_TOKEN"}
		},
	} {
		config := base
		mutate(&config)
		data, _ := json.Marshal([]sourceConfig{config})
		if _, err := LoadConfig(string(data), getenv); err == nil || strings.Contains(err.Error(), "private-token") {
			t.Fatalf("无效 Authentik 配置获准或泄露: %+v", config)
		}
	}
	// 服务账号开关只属于 Authentik
	other := sourceConfig{ID: uuid.New(), GroupID: uuid.New(), Kind: "keycloak", URL: "https://sso.invalid", Realm: "one", TokenEnv: "AUTHENTIK_TOKEN", IncludeServiceAccounts: true}
	data, _ := json.Marshal([]sourceConfig{other})
	if _, err := LoadConfig(string(data), getenv); err == nil {
		t.Fatal("其他目录接受了 includeServiceAccounts")
	}
}
