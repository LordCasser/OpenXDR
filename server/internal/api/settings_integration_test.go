//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openxdr/server/internal/aiconf"
	"openxdr/server/internal/notify"
	"openxdr/server/internal/testdb"
)

// 保存后读回一致；非法格式与非 http(s) 地址拒绝；测试推送打到表单里的地址。
func TestNotifySettings(t *testing.T) {
	_, client := testdb.New(t)
	var hits []string
	failed := false
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		hits = append(hits, string(b))
		if failed {
			_, _ = w.Write([]byte(`{"code":9499}`))
		} else {
			_, _ = w.Write([]byte(`{"code":0}`))
		}
	}))
	t.Cleanup(hook.Close)

	settings := &notify.Settings{DB: client, Default: notify.Target{Format: "generic"}}
	ts := httptest.NewServer(Settings(client, settings, &notify.Webhook{Settings: settings}, &aiconf.Store{DB: client}, nil))
	t.Cleanup(ts.Close)

	do := func(method, path, body string) *http.Response {
		req, _ := http.NewRequest(method, ts.URL+path, bytes.NewBufferString(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	for _, bad := range []string{`{"url":"ftp://x","format":"generic"}`, `{"url":"http://x","format":"slack"}`, `{"minSeverity":9}`} {
		if resp := do(http.MethodPut, "/api/settings/notify", bad); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s 应被拒绝，实际 %d", bad, resp.StatusCode)
		}
	}

	if resp := do(http.MethodPost, "/api/settings/notify/test", `{"url":"`+hook.URL+`","format":"feishu"}`); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("测试推送应成功，实际 %d", resp.StatusCode)
	}
	if len(hits) != 1 || !strings.Contains(hits[0], `"msg_type":"text"`) {
		t.Fatalf("测试推送应按飞书格式打到表单地址，实际 %v", hits)
	}
	if got := settings.Load(t.Context()); got.URL != "" {
		t.Fatal("测试推送不应保存配置")
	}

	failed = true
	if resp := do(http.MethodPost, "/api/settings/notify/test", `{"url":"`+hook.URL+`","format":"feishu"}`); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("业务拒绝应返回 502，实际 %d", resp.StatusCode)
	}
	failed = false

	body := `{"url":"` + hook.URL + `","format":"dingtalk","linkBase":"https://xdr.example.com","minSeverity":3}`
	if resp := do(http.MethodPut, "/api/settings/notify", body); resp.StatusCode != http.StatusOK {
		t.Fatalf("保存应成功，实际 %d", resp.StatusCode)
	}
	var got notify.Target
	resp := do(http.MethodGet, "/api/settings/notify", "")
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.URL != hook.URL || got.Format != "dingtalk" || got.MinSeverity != 3 || got.LinkBase != "https://xdr.example.com" {
		t.Errorf("读回不一致：%+v", got)
	}
}
