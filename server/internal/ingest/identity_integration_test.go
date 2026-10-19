//go:build integration

package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func windowsIdentityEvent(asset uuid.UUID, sid string, success bool) Envelope {
	id, status := 4625, 2
	if success {
		id, status = 4624, 1
	}
	raw, _ := json.Marshal(map[string]any{"event_id": id, "log_name": "Security", "activity_id": 1, "status_id": status,
		"user": map[string]string{"name": "alice", "domain": "CONTOSO", "uid": sid}, "session": map[string]string{"uid": "0x123"}})
	return Envelope{Version: EnvelopeVersion, ID: uuid.New(), PartitionKey: asset.String(), Timestamp: time.Now().UTC().Truncate(time.Microsecond), ClassUID: 3002, Source: "agent", AssetID: &asset, AssetOS: "windows", Username: "alice", Raw: raw}
}

func TestWindowsIdentityObservationScopeAndReplay(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	ctx := context.Background()
	group := uuid.New()
	a, err := client.Asset.Create().SetHostname("windows-one").SetOs("windows").SetGroupID(group).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := client.Asset.Create().SetHostname("windows-two").SetOs("windows").SetGroupID(group).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first := windowsIdentityEvent(a.ID, "S-1-5-21-1-2-3-1001", true)
	second := windowsIdentityEvent(b.ID, "S-1-5-21-1-2-3-1001", true)
	for _, e := range []Envelope{first, first, second} {
		if err := p.Process(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	var keys int
	if err := db.QueryRow(`SELECT count(DISTINCT account_key) FROM identity_observations`).Scan(&keys); err != nil || keys != 2 {
		t.Fatalf("同名/SID 不应跨设备合并: %d %v", keys, err)
	}
	movedGroup := uuid.New()
	if err := client.Asset.UpdateOneID(a.ID).SetGroupID(movedGroup).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	// 重投旧事件必须保留原观察归组，不依据当前组重解释。
	if err := p.Process(ctx, first); err != nil {
		t.Fatal(err)
	}
	moved := windowsIdentityEvent(a.ID, "S-1-5-21-1-2-3-1001", true)
	if err := p.Process(ctx, moved); err != nil {
		t.Fatal(err)
	}
	var originalGroup uuid.UUID
	if err := db.QueryRow(`SELECT group_id FROM identity_observations WHERE event_id=$1`, first.ID).Scan(&originalGroup); err != nil || originalGroup != group {
		t.Fatalf("旧观察归组被改写: %s %v", originalGroup, err)
	}
	if err := db.QueryRow(`SELECT count(DISTINCT account_key) FROM identity_observations`).Scan(&keys); err != nil || keys != 3 {
		t.Fatalf("换组应隔离账号键: %d %v", keys, err)
	}
}

func TestWindowsIdentityUnknownFailureAndInvalidEvidence(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	ctx := context.Background()
	a, err := client.Asset.Create().SetHostname("windows").SetOs("windows").SetGroupID(uuid.New()).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ sid, state string }{{"S-1-0-0", "missing_sid"}, {"not-a-sid", "invalid"}, {"S-1-5-21-1-2-3-1001", "observed"}} {
		e := windowsIdentityEvent(a.ID, tc.sid, false)
		if err := p.Process(ctx, e); err != nil {
			t.Fatal(err)
		}
		var state string
		var key, session sql.NullString
		var success sql.NullBool
		if err := db.QueryRow(`SELECT state,account_key,logon_id,success FROM identity_observations WHERE event_id=$1`, e.ID).Scan(&state, &key, &session, &success); err != nil {
			t.Fatal(err)
		}
		if state != tc.state || session.Valid || success.Bool {
			t.Fatalf("失败不能生成已认证会话: %s %+v %+v", state, session, success)
		}
		if tc.state != "observed" && key.Valid {
			t.Fatal("缺少或非法 SID 不能补造账号")
		}
		if _, err := client.Event.Get(ctx, e.ID); err != nil {
			t.Fatal("坏身份字段不应丢掉原始事件")
		}
	}
}

func TestIdentityWriteFailureRollsBackEvent(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	ctx := context.Background()
	a, err := client.Asset.Create().SetHostname("windows-rollback").SetOs("windows").SetGroupID(uuid.New()).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ALTER TABLE identity_observations ADD CONSTRAINT reject_identity CHECK(state <> 'observed') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`ALTER TABLE identity_observations DROP CONSTRAINT IF EXISTS reject_identity`)
	e := windowsIdentityEvent(a.ID, "S-1-5-21-1-2-3-1001", true)
	if err := p.Process(ctx, e); err == nil {
		t.Fatal("身份写入失败不能提交半笔事务")
	}
	if n, err := client.Event.Query().Count(ctx); err != nil || n != 0 {
		t.Fatalf("事件未回滚: %d %v", n, err)
	}
	if _, err := db.Exec(`ALTER TABLE identity_observations DROP CONSTRAINT reject_identity`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := p.Process(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM identity_observations`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("重试或重投错误: %d %v", n, err)
	}
	if err := client.Event.DeleteOneID(e.ID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM identity_observations`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("原事件删除后残留无证据关系: %d %v", n, err)
	}
}

func TestIdentityUsesDatabaseScopeAndOS(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	ctx := context.Background()
	asset, err := client.Asset.Create().SetHostname("unscoped").SetOs("windows").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e := windowsIdentityEvent(asset.ID, "S-1-5-21-1-2-3-1001", true)
	var raw map[string]any
	if err := json.Unmarshal(e.Raw, &raw); err != nil {
		t.Fatal(err)
	}
	raw["group_id"] = uuid.NewString()
	raw["asset_id"] = uuid.NewString()
	e.Raw, _ = json.Marshal(raw)
	if err := p.Process(ctx, e); err != nil {
		t.Fatal(err)
	}
	var state string
	var key sql.NullString
	var group uuid.NullUUID
	var observedAsset uuid.UUID
	if err := db.QueryRow(`SELECT state,account_key,group_id,asset_id FROM identity_observations WHERE event_id=$1`, e.ID).Scan(&state, &key, &group, &observedAsset); err != nil {
		t.Fatal(err)
	}
	if state != "unscoped" || key.Valid || group.Valid || observedAsset != asset.ID {
		t.Fatal("采信了日志自报的归属")
	}
	linux, err := client.Asset.Create().SetHostname("linux").SetOs("linux").SetGroupID(uuid.New()).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	spoofed := windowsIdentityEvent(linux.ID, "S-1-5-21-1-2-3-1001", true)
	if err := p.Process(ctx, spoofed); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM identity_observations WHERE event_id=$1`, spoofed.ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("仅靠信封 OS 不能伪造 Windows 来源: %d %v", n, err)
	}
}
