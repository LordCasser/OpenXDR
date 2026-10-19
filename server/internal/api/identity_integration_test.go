//go:build integration

package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/identity"
	"openxdr/server/internal/testdb"
)

func TestIdentityObservationAuthorization(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := identity.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	a := client.Group.Create().SetName("identity-a").SaveX(ctx)
	b := client.Group.Create().SetName("identity-b").SaveX(ctx)
	asset := client.Asset.Create().SetHostname("identity-windows").SetOs("windows").SetGroupID(a.ID).SaveX(ctx)
	user := client.User.Create().SetUsername("identity-viewer").SetPasswordHash("unused").SetRole("viewer").SaveX(ctx)
	membership := client.GroupMember.Create().SetUserID(user.ID).SetGroupID(a.ID).SetRole("viewer").SaveX(ctx)
	handler := IdentityObservations(db)
	observe := func(raw string) uuid.UUID {
		t.Helper()
		e := client.Event.Create().SetTs(time.Now().Add(-time.Minute)).SetSource("agent").SetClassUID(3002).SetAssetID(asset.ID).SetRaw(json.RawMessage(raw)).SaveX(ctx)
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err := identity.ObserveWindows(ctx, tx, e.ID); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return e.ID
	}
	success := `{"event_id":4624,"log_name":"Security","activity_id":1,"status_id":1,"user":{"name":"alice","uid":"S-1-5-21-1001"},"session":{"uid":"0x1"}}`
	first := observe(success)
	query := func(u *ent.User, extra string, count int, truncated bool) []identityObservation {
		t.Helper()
		w := httptest.NewRecorder()
		as(u, handler).ServeHTTP(w, httptest.NewRequest("GET", "/api/identity-observations?assetId="+asset.ID.String()+extra, nil))
		if w.Code != 200 {
			t.Fatalf("status=%d: %s", w.Code, w.Body.String())
		}
		var result struct {
			Items     []identityObservation `json:"items"`
			Truncated bool                  `json:"truncated"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Items == nil || len(result.Items) != count || result.Truncated != truncated {
			t.Fatalf("unexpected result: %s", w.Body.String())
		}
		return result.Items
	}
	if got := query(user, "", 1, false); got[0].EventID != first || got[0].SID == nil || got[0].Success == nil || !*got[0].Success {
		t.Fatal("身份字段丢失")
	}
	client.Asset.UpdateOneID(asset.ID).SetGroupID(b.ID).ExecX(ctx)
	query(user, "", 0, false) // 旧组失去当前资产访问权。
	client.GroupMember.DeleteOne(membership).ExecX(ctx)
	memberB := client.GroupMember.Create().SetUserID(user.ID).SetGroupID(b.ID).SetRole("viewer").SaveX(ctx)
	query(user, "", 0, false) // 新组没有历史组访问权。
	second := observe(success)
	if got := query(user, "", 1, false); got[0].EventID != second {
		t.Fatal("新组看到了旧组观察")
	}
	client.GroupMember.Create().SetUserID(user.ID).SetGroupID(a.ID).SetRole("viewer").SaveX(ctx)
	query(user, "", 2, false)
	query(user, "&limit=1", 1, true)
	query(user, "&limit=2", 2, false)
	client.GroupMember.DeleteOne(memberB).ExecX(ctx)
	query(user, "", 0, false) // 撤销成员资格即时生效。
	admin := client.User.Create().SetUsername("identity-admin").SetPasswordHash("unused").SetRole("admin").SaveX(ctx)
	query(admin, "", 2, false)
	client.Asset.UpdateOneID(asset.ID).ClearGroupID().ExecX(ctx)
	third := observe(success)
	query(user, "", 0, false)
	got := query(admin, "", 3, false)
	found := false
	for _, row := range got {
		if row.EventID == third {
			found = true
			if row.GroupID != nil || row.State != "unscoped" {
				t.Fatal("未归组状态丢失")
			}
		}
	}
	if !found {
		t.Fatal("未返回未归组观察")
	}
	observe(`{"event_id":4625,"log_name":"Security","activity_id":1,"status_id":2,"user":{"name":"unknown"}}`)
	got = query(admin, "", 4, false)
	for _, row := range got {
		if row.Name != nil && *row.Name == "unknown" {
			if row.SID != nil || row.LogonID != nil || row.Success == nil || *row.Success {
				t.Fatal("失败登录制造了身份或会话")
			}
		}
	}
	// 相同时间按事件 ID 稳定排序。
	for i := 1; i < len(got); i++ {
		if got[i-1].Ts.Before(got[i].Ts) {
			t.Fatal("时间顺序错误")
		}
	}
	for _, extra := range []string{"&limit=0", "&limit=201", "&limit=x", "&from=bad", "&to=bad", "&from=2099-01-01T00:00:00Z"} {
		w := httptest.NewRecorder()
		as(user, handler).ServeHTTP(w, httptest.NewRequest("GET", "/api/identity-observations?assetId="+asset.ID.String()+extra, nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", extra, w.Code)
		}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/api/identity-observations", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("未认证: %d", w.Code)
	}
	for _, value := range []string{"", "bad", uuid.Nil.String()} {
		w = httptest.NewRecorder()
		as(user, handler).ServeHTTP(w, httptest.NewRequest("GET", "/api/identity-observations?assetId="+value, nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("assetId=%s: %d", value, w.Code)
		}
	}
	client.User.UpdateOne(admin).SetRole("viewer").ExecX(ctx)
	query(admin, "", 0, false)
}
