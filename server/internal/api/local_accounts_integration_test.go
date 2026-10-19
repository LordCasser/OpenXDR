//go:build integration

package api

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"openxdr/server/internal/identity"
	"openxdr/server/internal/testdb"
)

func TestLocalSnapshotsAuthorizationAndStates(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := identity.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	a := client.Group.Create().SetName("local-a").SaveX(ctx)
	b := client.Group.Create().SetName("local-b").SaveX(ctx)
	asset := client.Asset.Create().SetHostname("local").SetOs("linux").SetGroupID(a.ID).SaveX(ctx)
	user := client.User.Create().SetUsername("local-viewer").SetPasswordHash("unused").SetRole("viewer").SaveX(ctx)
	member := client.GroupMember.Create().SetUserID(user.ID).SetGroupID(a.ID).SetRole("viewer").SaveX(ctx)
	ids := map[string]string{}
	for _, state := range []string{"observed", "unavailable", "invalid"} {
		e := client.Event.Create().SetTs(time.Now().Add(-time.Minute)).SetSource("agent").SetClassUID(5001).SetAssetID(asset.ID).SetRaw(json.RawMessage(`{}`)).SaveX(ctx)
		if _, err := db.Exec(`INSERT INTO identity_local_snapshots(event_id,asset_id,group_id,state,source) VALUES($1,$2,$3,$4,'etc-passwd')`, e.ID, asset.ID, a.ID, state); err != nil {
			t.Fatal(err)
		}
		ids[state] = e.ID.String()
	}
	h := LocalAccountSnapshots(db)
	detail := func(id string, status int) map[string]json.RawMessage {
		t.Helper()
		w := httptest.NewRecorder()
		as(user, h).ServeHTTP(w, httptest.NewRequest("GET", "/api/local-account-snapshots/"+id, nil))
		if w.Code != status {
			t.Fatalf("详情状态 %d: %s", w.Code, w.Body.String())
		}
		var result map[string]json.RawMessage
		if status == 200 {
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
		}
		return result
	}
	for state, id := range ids {
		got := detail(id, 200)
		expected := "null"
		if state == "observed" {
			expected = "[]"
		}
		if string(got["items"]) != expected {
			t.Fatalf("清单状态混淆: %s", got["items"])
		}
	}
	if _, err := db.Exec(`INSERT INTO identity_local_accounts(event_id,name,uid,gid,shell) VALUES($1,'root',0,4294967295,'/bin/sh')`, ids["observed"]); err != nil {
		t.Fatal(err)
	}
	got := detail(ids["observed"], 200)
	var accounts []identity.LinuxAccount
	if err := json.Unmarshal(got["items"], &accounts); err != nil || len(accounts) != 1 || accounts[0].GID != 4294967295 || string(got["accountCount"]) != "1" {
		t.Fatalf("账号详情错误: %v %s", err, got["items"])
	}
	detail("bad", 400)
	query := func(extra string, count int, truncated bool) []localAccountSnapshot {
		t.Helper()
		w := httptest.NewRecorder()
		as(user, h).ServeHTTP(w, httptest.NewRequest("GET", "/api/local-account-snapshots?assetId="+asset.ID.String()+extra, nil))
		var result struct {
			Items     []localAccountSnapshot
			Truncated bool
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Items == nil || len(result.Items) != count || result.Truncated != truncated {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		return result.Items
	}
	for _, s := range query("", 3, false) {
		if (s.AccountCount != nil) != (s.State == "observed") {
			t.Fatal("失败被显示为零账号")
		}
	}
	query("&limit=1", 1, true)
	client.Asset.UpdateOneID(asset.ID).SetGroupID(b.ID).ExecX(ctx)
	query("", 0, false)
	detail(ids["observed"], 404)
	memberB := client.GroupMember.Create().SetUserID(user.ID).SetGroupID(b.ID).SetRole("viewer").SaveX(ctx)
	query("", 3, false)
	client.GroupMember.DeleteOne(member).ExecX(ctx)
	query("", 0, false)
	detail(ids["observed"], 404)
	client.GroupMember.DeleteOne(memberB).ExecX(ctx)
	user.Role = "admin"
	query("", 0, false)
	detail(ids["observed"], 404)
	for _, url := range []string{"/api/local-account-snapshots", "/api/local-account-snapshots?assetId=bad", "/api/local-account-snapshots?assetId=" + asset.ID.String() + "&limit=201"} {
		w := httptest.NewRecorder()
		as(user, h).ServeHTTP(w, httptest.NewRequest("GET", url, nil))
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/local-account-snapshots", nil))
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
}
