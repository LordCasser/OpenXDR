//go:build integration

package api

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/temporal"
	"openxdr/server/internal/testdb"
)

func TestTemporalRuleSnapshotHistory(t *testing.T) {
	ctx, c := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	root := filepath.Join("..", "..", "..")
	snapshot, err := temporal.LoadSnapshot(filepath.Join(root, "rules"), filepath.Join(root, "temporal-rules"))
	if err != nil {
		t.Fatal(err)
	}
	// 共享测试库里别的测试留下的归档会干扰版本列表；引用它们的事件已随清表删除
	if _, err := db.Exec(`DELETE FROM temporal_rule_snapshots`); err != nil {
		t.Fatal(err)
	}
	// 两个历史版本：当前仓库规则（较新）与一个较旧的空规则版本；外加一个被改动的归档
	if _, err := db.Exec(`INSERT INTO temporal_rule_snapshots(revision,document,created_at) VALUES($1,$2::jsonb,now()-interval '1 day')`, snapshot.Revision(), string(snapshot.Archive())); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO temporal_rule_snapshots(revision,document,created_at) VALUES('old-empty','{}',now()-interval '3 days')`); err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(snapshot.Archive()), "threshold: 5", "threshold: 50", 1)
	if _, err := db.Exec(`INSERT INTO temporal_rule_snapshots(revision,document,created_at) VALUES('tampered',$1::jsonb,now()-interval '2 days')`, tampered); err != nil {
		t.Fatal(err)
	}
	group := c.Group.Create().SetName("rules-a").SaveX(ctx)
	other := c.Group.Create().SetName("rules-b").SaveX(ctx)
	asset := c.Asset.Create().SetHostname("rules-host").SetGroupID(group.ID).SaveX(ctx)
	analyst := c.User.Create().SetUsername("rules-analyst").SetPasswordHash("unused").SetRole("analyst").SaveX(ctx)
	outsider := c.User.Create().SetUsername("rules-outsider").SetPasswordHash("unused").SetRole("analyst").SaveX(ctx)
	viewer := c.User.Create().SetUsername("rules-viewer").SetPasswordHash("unused").SetRole("viewer").SaveX(ctx)
	admin := c.User.Create().SetUsername("rules-admin").SetPasswordHash("unused").SetRole("admin").SaveX(ctx)
	c.GroupMember.Create().SetUserID(analyst.ID).SetGroupID(group.ID).SetRole("analyst").SaveX(ctx)
	c.GroupMember.Create().SetUserID(outsider.ID).SetGroupID(other.ID).SetRole("analyst").SaveX(ctx)
	c.GroupMember.Create().SetUserID(viewer.ID).SetGroupID(group.ID).SetRole("viewer").SaveX(ctx)
	e := c.Event.Create().SetTs(time.Now()).SetAssetID(asset.ID).SetSource("agent").SetClassUID(3002).SetRaw(json.RawMessage(`{}`)).SaveX(ctx)
	rule := "temporal:linux-account-auth-burst"
	alert := c.Alert.Create().SetTs(time.Now()).SetRuleID(rule).SetSeverity(4).SetEventID(e.ID).SetAssetID(asset.ID).SaveX(ctx)
	plain := c.Alert.Create().SetTs(time.Now()).SetRuleID("single").SetSeverity(3).SetEventID(e.ID).SetAssetID(asset.ID).SaveX(ctx)
	if _, err := db.Exec(`INSERT INTO temporal_detections(revision,rule_id,anchor_id,group_id,entity,evidence,alert_id) VALUES($1,$2,$3,$4,'account:admin',$5,$6)`,
		snapshot.Revision(), rule, e.ID, group.ID, `["`+e.ID.String()+`"]`, alert.ID); err != nil {
		t.Fatal(err)
	}

	h := TemporalRuleSnapshots(db)
	get := func(user *ent.User, path string, want int) []byte {
		t.Helper()
		w := httptest.NewRecorder()
		as(user, h).ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != want {
			t.Fatalf("%s status=%d want %d: %s", path, w.Code, want, w.Body.String())
		}
		return w.Body.Bytes()
	}
	list := func(user *ent.User, query string) ([]temporalRuleVersion, bool) {
		t.Helper()
		var out struct {
			Items     []temporalRuleVersion `json:"items"`
			Truncated bool                  `json:"truncated"`
		}
		if err := json.Unmarshal(get(user, "/api/temporal-rule-snapshots"+query, 200), &out); err != nil || out.Items == nil {
			t.Fatalf("列表格式错误: %v", err)
		}
		return out.Items, out.Truncated
	}

	items, truncated := list(analyst, "")
	if len(items) != 3 || truncated || items[0].Revision != snapshot.Revision() || items[1].Revision != "tampered" || items[2].Revision != "old-empty" {
		t.Fatalf("应按首次使用时间倒序列出版本: %+v", items)
	}
	if items[0].Format != 1 || items[0].BaseRuleCount == 0 || len(items[0].TemporalRules) != 3 || items[2].BaseRuleCount != 0 || len(items[2].TemporalRules) != 0 {
		t.Fatalf("版本元数据错误: %+v", items)
	}
	if items, truncated := list(analyst, "?limit=1"); len(items) != 1 || !truncated {
		t.Fatal("limit 截断未提示")
	}
	// 告警 → 当时版本：只返回调用者看得到的告警所绑定的版本
	for user, want := range map[*ent.User]int{analyst: 1, admin: 1, outsider: 0} {
		if items, _ := list(user, "?alertId="+alert.ID.String()); len(items) != want || (want == 1 && items[0].Revision != snapshot.Revision()) {
			t.Fatalf("%s 按告警查版本错误: %+v", user.Username, items)
		}
	}
	if items, _ := list(analyst, "?alertId="+plain.ID.String()); len(items) != 0 {
		t.Fatal("单事件告警不应关联时序版本")
	}

	var detail struct {
		Revision string                  `json:"revision"`
		Rules    []temporal.ArchivedRule `json:"rules"`
	}
	if err := json.Unmarshal(get(analyst, "/api/temporal-rule-snapshots/"+snapshot.Revision()+"?rule="+rule, 200), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Revision != snapshot.Revision() || len(detail.Rules) != 1 {
		t.Fatalf("按版本取规则错误: %+v", detail)
	}
	got := detail.Rules[0]
	if got.ID != rule || got.GroupBy != "account" || got.Threshold != 5 || !strings.Contains(got.Source, "group_by: account") || !strings.Contains(got.Base[got.References[0]], "status_id: 2") {
		t.Fatalf("规则原文或引用的基础规则缺失: %+v", got)
	}
	if err := json.Unmarshal(get(admin, "/api/temporal-rule-snapshots/"+snapshot.Revision(), 200), &detail); err != nil || len(detail.Rules) != 3 {
		t.Fatalf("全量时序规则错误: %v", err)
	}
	get(analyst, "/api/temporal-rule-snapshots/"+snapshot.Revision()+"?rule=missing", 404)
	get(analyst, "/api/temporal-rule-snapshots/unknown", 404)
	get(analyst, "/api/temporal-rule-snapshots/tampered", 500)
	get(analyst, "/api/temporal-rule-snapshots/old-empty", 500)
	for _, q := range []string{"?limit=0", "?limit=101", "?limit=x", "?alertId=bad"} {
		get(analyst, "/api/temporal-rule-snapshots"+q, 400)
	}
	// viewer 不可读；降权以库中角色为准，请求上下文里的旧角色不放行
	get(viewer, "/api/temporal-rule-snapshots", 403)
	get(viewer, "/api/temporal-rule-snapshots/"+snapshot.Revision(), 403)
	c.User.UpdateOneID(analyst.ID).SetRole("viewer").ExecX(ctx)
	get(analyst, "/api/temporal-rule-snapshots", 403)
	get(analyst, "/api/temporal-rule-snapshots/"+snapshot.Revision(), 403)
}
