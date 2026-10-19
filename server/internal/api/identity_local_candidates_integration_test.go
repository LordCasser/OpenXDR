//go:build integration

package api

import (
	"database/sql"
	"encoding/json"
	"github.com/google/uuid"
	"net/http/httptest"
	"openxdr/server/internal/identity"
	"openxdr/server/internal/testdb"
	"os"
	"testing"
	"time"
)

func TestLocalIdentityCandidatesScopeAndTime(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := identity.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	group := client.Group.Create().SetName("candidate-local").SaveX(ctx)
	other := client.Group.Create().SetName("candidate-other").SaveX(ctx)
	asset := client.Asset.Create().SetHostname("candidate-host").SetOs("linux").SetGroupID(group.ID).SaveX(ctx)
	user := client.User.Create().SetUsername("candidate-user").SetRole("viewer").SetPasswordHash("unused").SaveX(ctx)
	member := client.GroupMember.Create().SetUserID(user.ID).SetGroupID(group.ID).SetRole("viewer").SaveX(ctx)
	now := time.Now().UTC().Truncate(time.Microsecond)
	login := client.Event.Create().SetTs(now).SetSource("agent").SetClassUID(3002).SetAssetID(asset.ID).SetRaw(json.RawMessage(`{}`)).SaveX(ctx)
	if _, err := db.Exec(`INSERT INTO identity_observations(event_id,asset_id,group_id,account_name,state) VALUES($1,$2,$3,'root','missing_uid')`, login.ID, asset.ID, group.ID); err != nil {
		t.Fatal(err)
	}
	add := func(ts time.Time, g uuid.UUID, name string) {
		t.Helper()
		e := client.Event.Create().SetTs(ts).SetSource("agent").SetClassUID(5001).SetAssetID(asset.ID).SetRaw(json.RawMessage(`{}`)).SaveX(ctx)
		if _, err := db.Exec(`INSERT INTO identity_local_snapshots(event_id,asset_id,group_id,state,source) VALUES($1,$2,$3,'observed','etc-passwd')`, e.ID, asset.ID, g); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO identity_local_accounts(event_id,name,uid,gid,shell) VALUES($1,$2,0,0,'/bin/sh')`, e.ID, name); err != nil {
			t.Fatal(err)
		}
	}
	add(now.Add(-time.Hour), group.ID, "root")
	add(now.Add(time.Second), group.ID, "root")
	add(now.Add(-25*time.Hour), group.ID, "root")
	add(now.Add(-time.Minute), other.ID, "root")
	add(now.Add(-time.Minute), group.ID, "different")
	h := IdentityCandidates(db)
	query := func(status, count int, truncated bool) {
		t.Helper()
		w := httptest.NewRecorder()
		as(user, h).ServeHTTP(w, httptest.NewRequest("GET", "/api/identity-observations/"+login.ID.String()+"/local-accounts", nil))
		if w.Code != status {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		if status != 200 {
			return
		}
		var result struct {
			Items     []localIdentityCandidate
			Truncated bool
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || len(result.Items) != count || result.Truncated != truncated {
			t.Fatalf("%s %v", w.Body.String(), err)
		}
	}
	query(200, 1, false)
	for range 21 {
		add(now.Add(-2*time.Hour), group.ID, "root")
	}
	query(200, 20, true)
	client.Asset.UpdateOneID(asset.ID).SetGroupID(other.ID).ExecX(ctx)
	query(404, 0, false)
	client.GroupMember.Create().SetUserID(user.ID).SetGroupID(other.ID).SetRole("viewer").SaveX(ctx)
	query(200, 20, true)
	client.GroupMember.DeleteOne(member).ExecX(ctx)
	query(404, 0, false)
	user.Role = "admin"
	query(404, 0, false)
}
