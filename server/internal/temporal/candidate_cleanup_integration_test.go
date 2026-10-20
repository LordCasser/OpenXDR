//go:build integration

package temporal_test

import (
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/temporal"
	"openxdr/server/internal/testdb"
)

func TestPruneCandidatesKeepsLiveWindowsAndEvidence(t *testing.T) {
	ctx, c := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	group := uuid.New()
	asset := c.Asset.Create().SetHostname("candidate-cleanup").SetGroupID(group).SaveX(ctx)
	current, other := "current-"+uuid.NewString(), "other-"+uuid.NewString()
	for _, revision := range []string{current, other} {
		if _, err := db.Exec(`INSERT INTO temporal_rule_snapshots(revision,document) VALUES($1,'{}')`, revision); err != nil {
			t.Fatal(err)
		}
	}
	window := 10 * time.Minute
	// 当前版本保留「窗口 + 迟到余量 + 事务余量(10 分钟)」，其他版本按 24 小时窗口计。
	keep := window + temporal.LateGrace + 10*time.Minute
	keepOther := 24*time.Hour + temporal.LateGrace + 10*time.Minute
	cases := []struct {
		name     string
		revision string
		age      time.Duration
		kept     bool
	}{
		{"当前版本过期", current, keep + time.Minute, false},
		{"当前版本仍可能被迟到事件读取", current, keep - time.Minute, true},
		{"当前版本新候选", current, time.Minute, true},
		{"旧版本未超 24 小时窗口", other, keep + time.Minute, true},
		{"旧版本过期", other, keepOther + time.Minute, false},
	}
	ids := map[string]uuid.UUID{}
	for _, tc := range cases {
		e := c.Event.Create().SetTs(time.Now().Add(-tc.age)).SetAssetID(asset.ID).SetClassUID(1007).SetSource("agent").SetRaw(json.RawMessage(`{}`)).SaveX(ctx)
		ids[tc.name] = e.ID
		if _, err := db.Exec(`INSERT INTO temporal_candidates(revision,event_id,asset_id,group_id,ts,rules) VALUES($1,$2,$3,$4,$5,'["base"]')`, tc.revision, e.ID, asset.ID, group, e.Ts); err != nil {
			t.Fatal(err)
		}
	}
	// 过期候选所属事件同时是一条已落库命中的前序证据：删候选不能动证据与原始事件。
	expired := ids["当前版本过期"]
	anchor := ids["当前版本新候选"]
	if _, err := db.Exec(`INSERT INTO temporal_detections(revision,rule_id,anchor_id,group_id,entity,evidence) VALUES($1,'burst',$2,$3,$4,$5)`,
		current, anchor, group, asset.ID.String(), `["`+expired.String()+`","`+anchor.String()+`"]`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO temporal_evidence(revision,rule_id,anchor_id,event_id) VALUES($1,'burst',$2,$3)`, current, anchor, expired); err != nil {
		t.Fatal(err)
	}
	n, err := temporal.PruneCandidates(ctx, db, current, window)
	if err != nil || n != 2 {
		t.Fatalf("应只删两条过期候选: %d %v", n, err)
	}
	for _, tc := range cases {
		var found bool
		if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM temporal_candidates WHERE event_id=$1)`, ids[tc.name]).Scan(&found); err != nil {
			t.Fatal(err)
		}
		if found != tc.kept {
			t.Fatalf("%s: 保留=%v 期望 %v", tc.name, found, tc.kept)
		}
	}
	var evidence, events int
	if err := db.QueryRow(`SELECT count(*) FROM temporal_evidence WHERE event_id=$1`, expired).Scan(&evidence); err != nil || evidence != 1 {
		t.Fatalf("证据关系被清理: %d %v", evidence, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM events WHERE id=$1`, expired).Scan(&events); err != nil || events != 1 {
		t.Fatalf("证据原始事件被清理: %d %v", events, err)
	}
	if n, err := temporal.PruneCandidates(ctx, db, current, window); err != nil || n != 0 {
		t.Fatalf("重复清理应无删除: %d %v", n, err)
	}
	// 旧版本候选清空且无其他引用后，归档可被释放。
	if _, err := db.Exec(`UPDATE temporal_rule_snapshots SET created_at=now()-interval '2 days' WHERE revision=$1`, other); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM temporal_candidates WHERE revision=$1`, other); err != nil {
		t.Fatal(err)
	}
	if n, err := temporal.PruneArchives(ctx, db, time.Now().Add(-24*time.Hour)); err != nil || n != 1 {
		t.Fatalf("旧版本归档未释放: %d %v", n, err)
	}
}
