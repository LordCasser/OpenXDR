//go:build integration

package ingest

import (
	"context"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestLinuxAccountSnapshotsTransactionAndReplay(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	ctx := context.Background()
	group := uuid.New()
	a, err := client.Asset.Create().SetHostname("local-accounts").SetOs("linux").SetGroupID(group).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e := Envelope{Version: EnvelopeVersion, ID: uuid.New(), PartitionKey: a.ID.String(), Timestamp: time.Now().UTC(), ClassUID: 5001, Source: "agent", AssetID: &a.ID, AssetOS: "linux", Raw: []byte(`{"activity_id":2,"device":{"local_accounts":{"version":1,"source":"etc-passwd","state":"observed","items":[{"name":"root","uid":0,"gid":0,"shell":"/bin/sh"},{"name":"alias","uid":0,"gid":4294967295,"shell":""}]}}}`)}
	if _, err := db.Exec(`ALTER TABLE identity_local_accounts ADD CONSTRAINT reject_local_test CHECK(name<>'alias') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`ALTER TABLE identity_local_accounts DROP CONSTRAINT IF EXISTS reject_local_test`)
	if err := p.Process(ctx, e); err == nil {
		t.Fatal("账号写入失败未回滚")
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM events WHERE id=$1`, e.ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("原事件未回滚: %d %v", n, err)
	}
	if _, err := db.Exec(`ALTER TABLE identity_local_accounts DROP CONSTRAINT reject_local_test`); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := client.Asset.UpdateOneID(a.ID).SetGroupID(uuid.New()).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(ctx, e); err != nil {
		t.Fatal(err)
	}
	var savedGroup uuid.UUID
	if err := db.QueryRow(`SELECT group_id FROM identity_local_snapshots WHERE event_id=$1`, e.ID).Scan(&savedGroup); err != nil || savedGroup != group {
		t.Fatalf("重放改写归组: %v", err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM identity_local_accounts WHERE event_id=$1`, e.ID).Scan(&n); err != nil || n != 2 {
		t.Fatalf("共享 UID 或重放错误: %d %v", n, err)
	}
	for _, tc := range []struct{ payload, state string }{
		{`"state":"unavailable"`, "unavailable"}, {`"state":"observed","items":[]`, "observed"}, {`"state":"observed","items":[{}]`, "invalid"},
	} {
		next := e
		next.ID = uuid.New()
		next.Timestamp = e.Timestamp.Add(-time.Hour)
		next.Raw = []byte(`{"activity_id":2,"device":{"local_accounts":{"version":1,"source":"etc-passwd",` + tc.payload + `}}}`)
		if err := p.Process(ctx, next); err != nil {
			t.Fatal(err)
		}
		var state string
		if err := db.QueryRow(`SELECT state FROM identity_local_snapshots WHERE event_id=$1`, next.ID).Scan(&state); err != nil || state != tc.state {
			t.Fatalf("%s %v", state, err)
		}
	}
	if err := db.QueryRow(`SELECT count(*) FROM identity_local_accounts WHERE event_id=$1`, e.ID).Scan(&n); err != nil || n != 2 {
		t.Fatal("迟到/失败清单删除了旧账号")
	}
	if err := client.Event.DeleteOneID(e.ID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM identity_local_accounts WHERE event_id=$1`, e.ID).Scan(&n); err != nil || n != 0 {
		t.Fatal("事件删除后残留无来源账号")
	}
}

func TestLinuxLoginUnknownUIDAndReplay(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	ctx := context.Background()
	group := uuid.New()
	a := client.Asset.Create().SetHostname("linux-login").SetOs("linux").SetGroupID(group).SaveX(ctx)
	e := Envelope{Version: EnvelopeVersion, ID: uuid.New(), PartitionKey: a.ID.String(), Timestamp: time.Now().UTC(), ClassUID: 3002, Source: "agent", AssetID: &a.ID, AssetOS: "linux", Raw: []byte(`{"activity_id":1,"status_id":2,"user":{"name":"root","uid":"0"},"service":{"name":"sshd"},"session":{"uid":"fake"}}`)}
	for range 2 {
		if err := p.Process(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	var state, name string
	var success bool
	var empty bool
	if err := db.QueryRow(`SELECT state,account_name,success,account_key IS NULL AND account_sid IS NULL AND logon_id IS NULL FROM identity_observations WHERE event_id=$1`, e.ID).Scan(&state, &name, &success, &empty); err != nil || state != "missing_uid" || name != "root" || success || !empty {
		t.Fatalf("登录被误归属: %s %v", state, err)
	}
}
