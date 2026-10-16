//go:build integration

package api

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

func TestAPIReportRender(t *testing.T) {
	ctx, client := testdb.New(t)
	gA := client.Group.Create().SetName("A").SaveX(ctx)
	gB := client.Group.Create().SetName("B").SaveX(ctx)
	session := client.AgentSession.Create().SetKind("task").SetGroupID(gA.ID).SetInitiator("system").SetModel("m").SaveX(ctx)
	rep := client.Report.Create().SetSessionID(session.ID).SetGroupID(gA.ID).SetTitle("日报").
		SetMarkdown("# 结论\n\n<script>alert(1)</script>").SaveX(ctx)
	bob := client.User.Create().SetUsername("bob").SetPasswordHash("x").SetRole("viewer").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(gB.ID).SetUserID(bob.ID).SetRole("viewer").SaveX(ctx)

	h := Handler(client, loadRules(t), t.TempDir(), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil, nil)
	admin := httptest.NewServer(asAdmin(h))
	t.Cleanup(admin.Close)
	other := httptest.NewServer(as(bob, h))
	t.Cleanup(other.Close)

	resp, body := get(t, admin, "/api/agent-reports/"+rep.ID.String()+"/html")
	if resp.StatusCode != 200 || !strings.Contains(string(body), "<h1>结论</h1>") || strings.Contains(string(body), "<script>") {
		t.Errorf("HTML 渲染不符：%d %s", resp.StatusCode, body)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("缺少 CSP：%q", csp)
	}
	if resp, _ := get(t, other, "/api/agent-reports/"+rep.ID.String()+"/html"); resp.StatusCode != 403 {
		t.Errorf("别组用户应 403，得到 %d", resp.StatusCode)
	}

	r, _ := postJSON(admin, "/api/users", `{"username":"system","password":"12345678","role":"viewer"}`)
	r.Body.Close()
	if r.StatusCode != 400 {
		t.Errorf("system 用户名应保留，得到 %d", r.StatusCode)
	}
}
