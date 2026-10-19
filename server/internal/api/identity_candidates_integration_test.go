//go:build integration

package api

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/identity"
	"openxdr/server/internal/identity/directory"
	"openxdr/server/internal/testdb"
)

func TestIdentityDirectoryCandidates(t *testing.T) {
	ctx, c := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := identity.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	a := c.Group.Create().SetName("candidate-a").SaveX(ctx)
	b := c.Group.Create().SetName("candidate-b").SaveX(ctx)
	u := c.User.Create().SetUsername("candidate-viewer").SetPasswordHash("unused").SetRole("viewer").SaveX(ctx)
	admin := c.User.Create().SetUsername("candidate-admin").SetPasswordHash("unused").SetRole("admin").SaveX(ctx)
	member := c.GroupMember.Create().SetUserID(u.ID).SetGroupID(a.ID).SetRole("viewer").SaveX(ctx)
	asset := c.Asset.Create().SetHostname("candidate-host").SetOs("windows").SetGroupID(a.ID).SaveX(ctx)
	e := c.Event.Create().SetTs(time.Now().Add(-time.Hour)).SetSource("agent").SetClassUID(3002).SetAssetID(asset.ID).SetRaw(json.RawMessage(`{"event_id":4624,"log_name":"Security","activity_id":1,"status_id":1,"user":{"name":"original","uid":"S-1-5-21-1-2-3-1001"}}`)).SaveX(ctx)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.ObserveWindows(ctx, tx, e.ID); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	addSource := func(group uuid.UUID, sid string) directory.Source {
		t.Helper()
		source := directory.Source{ID: uuid.New(), GroupID: group, Kind: "ad", Authority: "ldaps://directory.invalid/?base=dc%3Dexample"}
		if err := directory.RegisterSource(ctx, db, source); err != nil {
			t.Fatal(err)
		}
		if err := directory.SaveScan(ctx, db, directory.Scan{Source: source, StartedAt: time.Now().Add(-time.Minute), FinishedAt: time.Now(), Accounts: []directory.Account{{ExternalID: uuid.NewString(), Username: "renamed", WindowsSID: sid}}}); err != nil {
			t.Fatal(err)
		}
		return source
	}
	source := addSource(a.ID, "S-1-5-21-1-2-3-1001")
	addSource(b.ID, "S-1-5-21-1-2-3-1001")
	addSource(a.ID, "S-1-5-21-1-2-3-9999")
	h := IdentityCandidates(db)
	path := "/api/identity-observations/" + e.ID.String() + "/directory-accounts"
	check := func(user *ent.User, status, count int, ambiguous bool) []identityCandidate {
		t.Helper()
		w := httptest.NewRecorder()
		as(user, h).ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != status {
			t.Fatalf("状态 %d: %s", w.Code, w.Body.String())
		}
		if status != 200 {
			return nil
		}
		var out struct {
			Items     []identityCandidate `json:"items"`
			Ambiguous bool                `json:"ambiguous"`
			Truncated bool                `json:"truncated"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if len(out.Items) != count || out.Ambiguous != ambiguous || out.Truncated != (count == 20) {
			t.Fatalf("结果错误: %s", w.Body.String())
		}
		return out.Items
	}
	items := check(u, 200, 1, false)
	if items[0].SourceID != source.ID || !items[0].SeenInLatestSync || items[0].Enabled != nil {
		t.Fatal("来源或新鲜度错误")
	}
	// 后一次完整枚举未出现此账号，旧 SID 仍作为历史候选，明确不属于最近成功扫描。
	if err := directory.SaveScan(ctx, db, directory.Scan{Source: source, StartedAt: time.Now(), FinishedAt: time.Now(), Accounts: []directory.Account{}}); err != nil {
		t.Fatal(err)
	}
	if check(u, 200, 1, false)[0].SeenInLatestSync {
		t.Fatal("旧账号被描述为最新观察")
	}
	addSource(a.ID, "S-1-5-21-1-2-3-1001")
	check(u, 200, 2, true)
	c.Asset.UpdateOneID(asset.ID).SetGroupID(b.ID).ExecX(ctx)
	check(u, 404, 0, false)
	c.GroupMember.Create().SetUserID(u.ID).SetGroupID(b.ID).SetRole("viewer").SaveX(ctx)
	check(u, 200, 2, true)
	c.GroupMember.DeleteOne(member).ExecX(ctx)
	check(u, 404, 0, false)
	check(admin, 200, 2, true)
	c.User.UpdateOne(admin).SetRole("viewer").ExecX(ctx)
	check(admin, 404, 0, false)
	c.GroupMember.Create().SetUserID(u.ID).SetGroupID(a.ID).SetRole("viewer").SaveX(ctx)
	for range 19 {
		addSource(a.ID, "S-1-5-21-1-2-3-1001")
	}
	check(u, 200, 20, true)
	if _, err := db.ExecContext(ctx, `UPDATE identity_observations SET account_sid=NULL WHERE event_id=$1`, e.ID); err != nil {
		t.Fatal(err)
	}
	check(u, 200, 0, false)
	for _, url := range []string{"/api/identity-observations/bad/directory-accounts", "/api/identity-observations/00000000-0000-0000-0000-000000000000/directory-accounts"} {
		w := httptest.NewRecorder()
		as(u, h).ServeHTTP(w, httptest.NewRequest("GET", url, nil))
		if w.Code != 400 {
			t.Fatal("错误事件 ID 获准")
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	if w.Code != 401 {
		t.Fatal("未登录获准")
	}
}
