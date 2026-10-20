//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/ent/auditlog"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

func TestAPIFindings(t *testing.T) {
	ctx, client := testdb.New(t)
	gA := client.Group.Create().SetName("A").SaveX(ctx)
	gB := client.Group.Create().SetName("B").SaveX(ctx)
	hA := client.Asset.Create().SetHostname("pve1").SetGroupID(gA.ID).SaveX(ctx)
	hB := client.Asset.Create().SetHostname("pve2").SetGroupID(gB.ID).SaveX(ctx)
	fA := client.Finding.Create().SetGroupID(gA.ID).SetAssetID(hA.ID).SetKey("disk").SetTitle("磁盘将满").SaveX(ctx)
	client.Finding.Create().SetGroupID(gB.ID).SetAssetID(hB.ID).SetKey("secret").SetTitle("B组秘密").SaveX(ctx)
	alice := client.User.Create().SetUsername("alice").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(gA.ID).SetUserID(alice.ID).SetRole("viewer").SaveX(ctx)

	h := Handler(client, loadRules(t), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)
	admin := httptest.NewServer(asAdmin(h))
	t.Cleanup(admin.Close)
	viewer := httptest.NewServer(as(alice, h))
	t.Cleanup(viewer.Close)

	_, body := get(t, viewer, "/api/findings")
	var rows []findingRow
	if err := json.Unmarshal(body, &rows); err != nil || len(rows) != 1 || rows[0].Hostname != "pve1" || strings.Contains(string(body), "B组秘密") {
		t.Fatalf("待办越组或缺主机名：%s", body)
	}
	post := func(ts *httptest.Server, body string) int {
		resp, err := http.Post(ts.URL+"/api/findings/"+fA.ID.String()+"/status", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post(viewer, `{"status":"ignored","note":"x"}`); code != http.StatusForbidden {
		t.Errorf("组内 viewer 不能改待办，得到 %d", code)
	}
	if code := post(admin, `{"status":"ignored"}`); code != http.StatusBadRequest {
		t.Errorf("忽略不写原因应 400，得到 %d", code)
	}
	if code := post(admin, `{"status":"ignored","note":"计划下线"}`); code != http.StatusNoContent {
		t.Fatalf("忽略应 204，得到 %d", code)
	}
	if f := client.Finding.GetX(ctx, fA.ID); f.Status != "ignored" || f.Note == nil || *f.Note != "计划下线" || f.ResolvedBy == nil {
		t.Errorf("忽略未落库：%+v", f)
	}
	if n := client.AuditLog.Query().Where(auditlog.ActionEQ("finding_status"), auditlog.DetailEQ("ignored 计划下线")).CountX(ctx); n != 1 {
		t.Errorf("忽略应落审计，得到 %d 条", n)
	}
	if code := post(admin, `{"status":"open"}`); code != http.StatusNoContent || client.Finding.GetX(ctx, fA.ID).Note != nil {
		t.Errorf("重开应清掉原因，得到 %d", code)
	}
	_, body = get(t, admin, "/api/findings?status=open")
	if err := json.Unmarshal(body, &rows); err != nil || len(rows) != 2 {
		t.Errorf("管理员应看到全部遗留待办：%s", body)
	}
}
