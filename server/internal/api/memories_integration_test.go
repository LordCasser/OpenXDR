//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

// 记忆按组可见；组内 viewer 只能看，analyst 以上可增删改，人改过的变成人工记忆；主机必须属于该组
func TestAPIMemories(t *testing.T) {
	ctx, client := testdb.New(t)
	gA := client.Group.Create().SetName("A").SaveX(ctx)
	gB := client.Group.Create().SetName("B").SaveX(ctx)
	hA := client.Asset.Create().SetHostname("pve1").SetGroupID(gA.ID).SaveX(ctx)
	hB := client.Asset.Create().SetHostname("pve2").SetGroupID(gB.ID).SaveX(ctx)
	ai := client.Memory.Create().SetGroupID(gA.ID).SetAssetID(hA.ID).SetContent("AI 记的").SetSource("ai").SetAuthor("s").SaveX(ctx)
	client.Memory.Create().SetGroupID(gB.ID).SetContent("B组秘密").SetSource("human").SetAuthor("b").SaveX(ctx)
	alice := client.User.Create().SetUsername("alice").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(gA.ID).SetUserID(alice.ID).SetRole("viewer").SaveX(ctx)

	h := Handler(client, loadRules(t), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)
	admin := httptest.NewServer(asAdmin(h))
	t.Cleanup(admin.Close)
	viewer := httptest.NewServer(as(alice, h))
	t.Cleanup(viewer.Close)

	_, body := get(t, viewer, "/api/memories")
	var rows []memoryRow
	if err := json.Unmarshal(body, &rows); err != nil || len(rows) != 1 || rows[0].Hostname != "pve1" || strings.Contains(string(body), "B组秘密") {
		t.Fatalf("记忆越组或缺主机名：%s", body)
	}
	send := func(ts *httptest.Server, method, path, body string) int {
		req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := send(viewer, "POST", "/api/memories", `{"groupId":"`+gA.ID.String()+`","content":"x"}`); code != http.StatusForbidden {
		t.Errorf("组内 viewer 不能写记忆，得到 %d", code)
	}
	if code := send(admin, "POST", "/api/memories", `{"groupId":"`+gA.ID.String()+`","assetId":"`+hB.ID.String()+`","content":"x"}`); code != http.StatusBadRequest {
		t.Errorf("别组主机应 400，得到 %d", code)
	}
	if code := send(admin, "POST", "/api/memories", `{"groupId":"`+gA.ID.String()+`","content":"10.1.1.100 是网关容器"}`); code != http.StatusOK {
		t.Fatalf("新增应 200，得到 %d", code)
	}
	if code := send(admin, "PATCH", "/api/memories/"+ai.ID.String(), `{"content":"人改过"}`); code != http.StatusNoContent {
		t.Fatalf("修改应 204，得到 %d", code)
	}
	if m := client.Memory.GetX(ctx, ai.ID); m.Source != "human" || m.Content != "人改过" || m.Author != "admin" {
		t.Errorf("人改过的应变成人工记忆：%+v", m)
	}
	if code := send(admin, "DELETE", "/api/memories/"+ai.ID.String(), ""); code != http.StatusNoContent {
		t.Fatalf("删除应 204，得到 %d", code)
	}
	if n := client.AuditLog.Query().CountX(ctx); n != 3 {
		t.Errorf("增删改都要写审计，得到 %d 条", n)
	}
}
