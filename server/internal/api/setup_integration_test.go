//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"openxdr/server/internal/auth"
	"openxdr/server/internal/testdb"
)

// 同意协议要对上当前版本；先同意才能结束引导；已有组或主机的实例不再走引导
func TestSetupAgreementAndOnboarding(t *testing.T) {
	ctx, client := testdb.New(t)
	admin := client.User.Create().SetUsername("admin").SetPasswordHash("x").SetRole("admin").SaveX(ctx)
	h := Setup(client)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), admin)))
	}))
	t.Cleanup(ts.Close)
	do := func(method, path, body string) int {
		req, _ := http.NewRequest(method, ts.URL+path, bytes.NewBufferString(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	state := func() map[string]any {
		resp, err := http.Get(ts.URL + "/api/setup")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var s map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&s)
		return s
	}

	if s := state(); s["accepted"] != false || s["onboarded"] != false {
		t.Fatalf("全新安装应未同意、未引导: %v", s)
	}
	if code := do(http.MethodPost, "/api/setup/onboarded", `{"skipped":[]}`); code != http.StatusConflict {
		t.Fatalf("未同意协议不能结束引导，实际 %d", code)
	}
	if code := do(http.MethodPost, "/api/setup/agreement", `{"version":"old"}`); code != http.StatusConflict {
		t.Fatalf("旧版本协议不能算同意，实际 %d", code)
	}
	if code := do(http.MethodPost, "/api/setup/agreement", `{"version":"`+AgreementVersion+`"}`); code != http.StatusNoContent {
		t.Fatalf("同意协议失败: %d", code)
	}
	if s := state(); s["accepted"] != true || s["acceptedBy"] != "admin" || s["onboarded"] != false {
		t.Fatalf("同意后状态不对: %v", s)
	}
	if code := do(http.MethodPost, "/api/setup/onboarded", `{"skipped":["ai","webhook"]}`); code != http.StatusNoContent {
		t.Fatalf("结束引导失败: %d", code)
	}
	if s := state(); s["onboarded"] != true {
		t.Fatalf("引导应已结束: %v", s)
	}
	if n := client.AuditLog.Query().CountX(ctx); n != 2 {
		t.Fatalf("同意协议与结束引导都应落审计，实际 %d 条", n)
	}

	// 升级上来的实例：已有组就不再引导，但协议照样要同意
	client.Setting.DeleteOneID(setupKey).ExecX(ctx)
	client.Group.Create().SetName("prod").SaveX(ctx)
	if s := state(); s["accepted"] != false || s["onboarded"] != true {
		t.Fatalf("已有组的实例应跳过引导、仍需同意协议: %v", s)
	}
}
