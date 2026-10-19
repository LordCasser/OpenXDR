//go:build integration

package api

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
)

func TestTemporalGapScope(t *testing.T) {
	ctx, c := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	a := c.Group.Create().SetName("gap-a").SaveX(ctx)
	b := c.Group.Create().SetName("gap-b").SaveX(ctx)
	asset := c.Asset.Create().SetHostname("gap-host").SetGroupID(a.ID).SaveX(ctx)
	u := c.User.Create().SetUsername("gap-viewer").SetPasswordHash("unused").SetRole("viewer").SaveX(ctx)
	admin := c.User.Create().SetUsername("gap-admin").SetPasswordHash("unused").SetRole("admin").SaveX(ctx)
	m := c.GroupMember.Create().SetUserID(u.ID).SetGroupID(a.ID).SetRole("viewer").SaveX(ctx)
	if _, err := db.Exec(`INSERT INTO temporal_rule_snapshots(revision,document) VALUES('test-revision','{}') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		e := c.Event.Create().SetTs(time.Now()).SetAssetID(asset.ID).SetSource("agent").SetClassUID(1007).SetRaw(json.RawMessage(`{}`)).SaveX(ctx)
		if _, err := db.Exec(`INSERT INTO temporal_evaluation_gaps(revision,event_id,asset_id,group_id,reason,candidate_count_lower_bound,window_from,window_to) VALUES('test-revision',$1,$2,$3,'candidate_limit',10001,now()-interval '1 minute',now()+interval '1 minute')`, e.ID, asset.ID, a.ID); err != nil {
			t.Fatal(err)
		}
	}
	h := TemporalGaps(db)
	check := func(user *ent.User, query string, want int, truncated bool) {
		t.Helper()
		w := httptest.NewRecorder()
		as(user, h).ServeHTTP(w, httptest.NewRequest("GET", "/api/temporal-gaps?assetId="+asset.ID.String()+query, nil))
		if w.Code != 200 {
			t.Fatalf("status=%d %s", w.Code, w.Body.String())
		}
		var out struct {
			Items     []temporalGap `json:"items"`
			Truncated bool          `json:"truncated"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.Items == nil || len(out.Items) != want || out.Truncated != truncated {
			t.Fatalf("结果错误 %s", w.Body.String())
		}
		for _, g := range out.Items {
			if g.CandidateCountLowerBound != 10001 || g.GroupID != a.ID {
				t.Fatal("缺口元数据错误")
			}
		}
	}
	check(u, "", 2, false)
	check(u, "&limit=1", 1, true)
	check(u, "&limit=2", 2, false)
	check(u, "&from=2000-01-01T00:00:00Z&to=2000-01-02T00:00:00Z", 0, false)
	c.Asset.UpdateOneID(asset.ID).SetGroupID(b.ID).ExecX(ctx)
	check(u, "", 0, false)
	c.GroupMember.DeleteOne(m).ExecX(ctx)
	c.GroupMember.Create().SetUserID(u.ID).SetGroupID(b.ID).SetRole("viewer").SaveX(ctx)
	check(u, "", 0, false)
	both := c.GroupMember.Create().SetUserID(u.ID).SetGroupID(a.ID).SetRole("viewer").SaveX(ctx)
	check(u, "", 2, false)
	c.GroupMember.DeleteOne(both).ExecX(ctx)
	check(u, "", 0, false)
	check(admin, "", 2, false)
	c.Asset.UpdateOneID(asset.ID).ClearGroupID().ExecX(ctx)
	check(u, "", 0, false)
	check(admin, "", 2, false)
	for _, q := range []string{"&limit=0", "&limit=201", "&limit=no", "&from=bad", "&to=bad", "&from=2099-01-01T00:00:00Z"} {
		w := httptest.NewRecorder()
		as(u, h).ServeHTTP(w, httptest.NewRequest("GET", "/api/temporal-gaps?assetId="+asset.ID.String()+q, nil))
		if w.Code != 400 {
			t.Fatalf("%s: %d", q, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/temporal-gaps", nil))
	if w.Code != 401 {
		t.Fatal("未认证访问")
	}
	// 数据库降权应即时生效，即使请求上下文仍带旧角色。
	c.User.UpdateOne(admin).SetRole("viewer").ExecX(ctx)
	check(admin, "", 0, false)
}
