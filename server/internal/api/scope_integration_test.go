//go:build integration

package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

// 非 admin 只看得到自己组里的资产、事件、告警与 incident；跨组 incident 整体不可见，
// 组内 viewer 不能做写操作。
func TestAPIGroupScope(t *testing.T) {
	ctx, client := testdb.New(t)
	gA := client.Group.Create().SetName("A").SaveX(ctx)
	gB := client.Group.Create().SetName("B").SaveX(ctx)
	a1 := client.Asset.Create().SetHostname("a1").SetGroupID(gA.ID).SaveX(ctx)
	b1 := client.Asset.Create().SetHostname("b1").SetGroupID(gB.ID).SaveX(ctx)
	client.Asset.Create().SetHostname("loose").SaveX(ctx)

	alertOn := func(asset *ent.Asset, inc *ent.Incident) {
		evt := client.Event.Create().SetTs(time.Now()).SetClassUID(1007).SetSource("agent").
			SetAssetID(asset.ID).SetRaw(json.RawMessage(`{}`)).SaveX(ctx)
		client.Alert.Create().SetTs(time.Now()).SetRuleID("r").SetSeverity(3).
			SetEventID(evt.ID).SetAssetID(asset.ID).SetIncidentID(inc.ID).SaveX(ctx)
	}
	newInc := func(title string) *ent.Incident {
		return client.Incident.Create().SetTitle(title).SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	}
	incA, incB, incAB := newInc("A"), newInc("B"), newInc("AB")
	alertOn(a1, incA)
	alertOn(b1, incB)
	alertOn(a1, incAB)
	alertOn(b1, incAB)

	alice := client.User.Create().SetUsername("alice").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(gA.ID).SetUserID(alice.ID).SetRole("viewer").SaveX(ctx)

	h := Handler(client, loadRules(t), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)
	ts := httptest.NewServer(as(alice, h))
	t.Cleanup(ts.Close)

	count := func(path string) int {
		t.Helper()
		resp, body := get(t, ts, path)
		if resp.StatusCode != 200 {
			t.Fatalf("%s status = %d", path, resp.StatusCode)
		}
		var list []json.RawMessage
		if err := json.Unmarshal(body, &list); err != nil {
			t.Fatal(err)
		}
		return len(list)
	}
	if n := count("/api/assets"); n != 1 {
		t.Errorf("资产应只见 1 台，得到 %d", n)
	}
	if n := count("/api/events"); n != 2 {
		t.Errorf("事件应只见 a1 的 2 条，得到 %d", n)
	}
	if n := count("/api/incidents"); n != 1 {
		t.Errorf("incident 应只见 A，跨组的 AB 不可见，得到 %d", n)
	}
	for _, inc := range []*ent.Incident{incB, incAB} {
		if resp, _ := get(t, ts, "/api/incidents/"+inc.ID.String()); resp.StatusCode != 404 {
			t.Errorf("组外 incident %s 应 404，得到 %d", *inc.Title, resp.StatusCode)
		}
	}
	if resp, _ := get(t, ts, "/api/assets/"+b1.ID.String()+"/config"); resp.StatusCode != 404 {
		t.Errorf("组外资产配置应 404，得到 %d", resp.StatusCode)
	}

	var stats statsResponse
	_, body := get(t, ts, "/api/stats")
	if err := json.Unmarshal(body, &stats); err != nil {
		t.Fatal(err)
	}
	if stats.AssetsTotal != 1 || stats.Events24h != 2 || stats.Alerts24h != 2 || stats.IncidentsByStatus["open"] != 1 {
		t.Errorf("统计应按组裁剪：%+v", stats)
	}
	if stats.AlertsBySeverity[3] != 2 || len(stats.AlertsBySeverity) != 1 {
		t.Errorf("级别分布应只计组内 2 条中危：%v", stats.AlertsBySeverity)
	}
	// 资产详情：按主机筛事件与指令，组外主机筛出来也是空
	if n := count("/api/incidents?assetId=" + a1.ID.String()); n != 1 {
		t.Errorf("a1 涉及的可见 incident 应为 1，得到 %d", n)
	}
	if n := count("/api/incidents?assetId=" + b1.ID.String()); n != 0 {
		t.Errorf("组外主机的 incident 不可见，得到 %d", n)
	}
	if n := count("/api/commands?assetId=" + a1.ID.String()); n != 0 {
		t.Errorf("a1 没有指令，得到 %d", n)
	}

	// 组内只是 viewer：改 incident 状态与下发指令都不行
	r, _ := postJSON(ts, "/api/incidents/"+incA.ID.String()+"/status", `{"status":"closed","note":"x"}`)
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Errorf("viewer 改状态应被拒，得到 %d", r.StatusCode)
	}
	r, _ = postJSON(ts, "/api/commands", `{"kind":"exec","cmd":"id","assetId":"`+a1.ID.String()+`"}`)
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Errorf("viewer 下发指令应被拒，得到 %d", r.StatusCode)
	}
}
