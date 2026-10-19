//go:build integration

package ingest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/temporal"
)

func temporalStoreFixture(t *testing.T) *temporal.Store {
	return temporalStoreFixtureWithRule(t, "id: burst\nkind: event_count\nwithin: 1m\nrules: [base]\nthreshold: 2\nlevel: critical\n")
}

func temporalStoreFixtureWithRule(t *testing.T, rule string) *temporal.Store {
	t.Helper()
	base, seq := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "base.yml"), []byte(`id: base
title: Test
logsource:
  category: process_creation
detection:
  select:
    marker: yes
  condition: select
`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(seq, "count.yml"), []byte(rule), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "unrelated.yml"), []byte(`id: unrelated
title: Unrelated single event
logsource:
  category: process_creation
detection:
  select:
    standalone: yes
  condition: select
`), 0600); err != nil {
		t.Fatal(err)
	}
	store := &temporal.Store{}
	if err := store.Reload(base, seq); err != nil {
		t.Fatal(err)
	}
	return store
}

func temporalFixture(t *testing.T) *temporal.Snapshot { return temporalStoreFixture(t).Current() }

func TestTemporalPersistentLateReplayAndRollback(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	ctx := context.Background()
	snapshot := temporalFixture(t)
	asset, err := client.Asset.Create().SetHostname("temporal").SetGroupID(uuid.New()).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	event := Envelope{Version: EnvelopeVersion, ID: uuid.New(), PartitionKey: asset.ID.String(), Timestamp: now, ClassUID: 1007, Source: "agent", AssetID: &asset.ID, Raw: json.RawMessage(`{"marker":"yes"}`)}
	observe := func(e Envelope, commit bool) temporal.Observation {
		t.Helper()
		if err := p.Process(ctx, e); err != nil {
			t.Fatal(err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		result, err := snapshot.Observe(ctx, tx, e.ID, []string{"base"})
		if err != nil {
			t.Fatal(err)
		}
		if commit {
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}
		return result
	}
	if got := observe(event, true); len(got.Matches) != 0 || got.Unscoped {
		t.Fatalf("第一条不应命中: %+v", got)
	}
	late := event
	late.ID = uuid.New()
	late.Timestamp = now.Add(-time.Second)
	first := observe(late, false)
	if len(first.Matches) != 1 || first.Matches[0].Anchor != event.ID {
		t.Fatalf("应回看原终点: %+v", first)
	}
	// 回滚候选和命中后，再观察应重新给出同一命中。
	again := observe(late, true)
	if len(again.Matches) != 1 {
		t.Fatalf("回滚吞掉命中: %+v", again)
	}
	snapshot = temporalFixture(t) // 新对象相同版本，读取数据库状态
	if got := observe(late, true); len(got.Matches) != 0 {
		t.Fatalf("重启/重投重复命中: %+v", got)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.Observe(ctx, tx, late.ID, nil); err == nil {
		t.Fatal("同事件不同命中内容必须拒绝")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var evidence []byte
	if err := db.QueryRow(`SELECT evidence FROM temporal_detections WHERE anchor_id=$1`, event.ID).Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	var ids []uuid.UUID
	if err := json.Unmarshal(evidence, &ids); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != late.ID || ids[1] != event.ID {
		t.Fatalf("证据不完整: %v", ids)
	}
}

func TestTemporalAssetGroupRoundTripClearsCandidates(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	ctx := context.Background()
	snapshot := temporalFixture(t)
	group := uuid.New()
	asset, err := client.Asset.Create().SetHostname("move-group").SetGroupID(group).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e := Envelope{Version: EnvelopeVersion, ID: uuid.New(), PartitionKey: asset.ID.String(), Timestamp: time.Now().UTC().Truncate(time.Microsecond), ClassUID: 1007, Source: "agent", AssetID: &asset.ID, Raw: json.RawMessage(`{"marker":"yes"}`)}
	observe := func() temporal.Observation {
		t.Helper()
		if err := p.Process(ctx, e); err != nil {
			t.Fatal(err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		result, err := snapshot.Observe(ctx, tx, e.ID, []string{"base"})
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return result
	}
	observe()
	if _, err := client.Asset.UpdateOneID(asset.ID).SetGroupID(uuid.New()).Save(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Asset.UpdateOneID(asset.ID).SetGroupID(group).Save(ctx); err != nil {
		t.Fatal(err)
	}
	e.ID = uuid.New()
	e.Timestamp = e.Timestamp.Add(time.Second)
	if got := observe(); len(got.Matches) != 0 {
		t.Fatalf("跨换组周期拼接: %+v", got)
	}
	if _, err := client.Asset.UpdateOneID(asset.ID).ClearGroupID().Save(ctx); err != nil {
		t.Fatal(err)
	}
	e.ID = uuid.New()
	if got := observe(); !got.Unscoped || len(got.Matches) != 0 {
		t.Fatalf("未分组必须显式跳过: %+v", got)
	}
}

func TestProcessorTemporalAlertIsAtomicAndAnchored(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	p.Temporal = temporalStoreFixture(t)
	ctx := context.Background()
	asset, err := client.Asset.Create().SetHostname("live-temporal").SetGroupID(uuid.New()).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	terminal := Envelope{Version: EnvelopeVersion, ID: uuid.New(), PartitionKey: asset.ID.String(), Timestamp: now, ClassUID: 1007, Source: "agent", AssetID: &asset.ID, Raw: json.RawMessage(`{"marker":"yes"}`)}
	if err := p.Process(ctx, terminal); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ALTER TABLE alerts ADD CONSTRAINT test_reject_generic_temporal CHECK (rule_id <> 'burst') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`ALTER TABLE alerts DROP CONSTRAINT IF EXISTS test_reject_generic_temporal`)
	late := terminal
	late.ID = uuid.New()
	late.Timestamp = now.Add(-time.Second)
	if err := p.Process(ctx, late); err == nil {
		t.Fatal("必须传播时序告警失败")
	}
	for _, table := range []string{"events", "temporal_candidates"} {
		var n int
		if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil || n != 1 {
			t.Fatalf("%s 未完整回滚: %d %v", table, n, err)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM temporal_detections`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("命中记录未回滚: %d %v", n, err)
	}
	if _, err := db.Exec(`ALTER TABLE alerts DROP CONSTRAINT test_reject_generic_temporal`); err != nil {
		t.Fatal(err)
	}
	restarted := *p
	restarted.Temporal = temporalStoreFixture(t)
	for range 2 {
		if err := restarted.Process(ctx, late); err != nil {
			t.Fatal(err)
		}
	}
	var anchor uuid.UUID
	var count int
	var severity int16
	var ts time.Time
	if err := db.QueryRow(`SELECT event_id,count,ts,severity FROM alerts WHERE rule_id='burst'`).Scan(&anchor, &count, &ts, &severity); err != nil {
		t.Fatal(err)
	}
	var archived []byte
	if err := db.QueryRow(`SELECT document FROM temporal_rule_snapshots WHERE revision=$1`, restarted.Temporal.Current().Revision()).Scan(&archived); err != nil {
		t.Fatal(err)
	}
	restored, err := temporal.RestoreArchive(archived)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Revision() != restarted.Temporal.Current().Revision() || len(restored.EvaluateBase(1007, "linux", map[string]any{"marker": "yes"})) != 1 {
		t.Fatal("数据库规则归档无法重现命中")
	}
	var linked int
	if err := db.QueryRow(`SELECT count(*) FROM temporal_detections d JOIN temporal_evidence e
ON (d.revision,d.rule_id,d.anchor_id)=(e.revision,e.rule_id,e.anchor_id)
JOIN alerts a ON a.id=d.alert_id WHERE d.anchor_id=$1 AND e.event_id=$2`, terminal.ID, late.ID).Scan(&linked); err != nil || linked != 1 {
		t.Fatalf("命中未关联告警及原始证据: %d %v", linked, err)
	}
	if anchor != terminal.ID || count != 1 || severity != 5 || !ts.Equal(terminal.Timestamp) {
		t.Fatalf("时序告警归属或重投计数错误: %s %d %s", anchor, count, ts)
	}
}

func TestProcessorRejectsMissingTemporalSnapshot(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	p.Temporal = &temporal.Store{}
	e := Envelope{Version: EnvelopeVersion, ID: uuid.New(), PartitionKey: "a", Timestamp: time.Now(), ClassUID: 1007, Source: "agent", Raw: json.RawMessage(`{}`)}
	if err := p.Process(context.Background(), e); err == nil {
		t.Fatal("缺少有效规则快照不能按成功处理")
	}
	if n, err := client.Event.Query().Count(context.Background()); err != nil || n != 0 {
		t.Fatalf("失败不应提交事件: %d %v", n, err)
	}
}

func TestTemporalCandidatesExcludeUnrelatedEvents(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	p.Temporal = temporalStoreFixture(t)
	ctx := context.Background()
	asset, err := client.Asset.Create().SetHostname("candidate-filter").SetGroupID(uuid.New()).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e := Envelope{Version: EnvelopeVersion, PartitionKey: asset.ID.String(), Timestamp: time.Now().UTC().Truncate(time.Microsecond), ClassUID: 1007, Source: "agent", AssetID: &asset.ID}
	for _, raw := range []string{`{}`, `{"standalone":"yes"}`, `{"marker":"yes","standalone":"yes"}`} {
		e.ID = uuid.New()
		e.Raw = json.RawMessage(raw)
		if err := p.Process(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	var candidates, events int
	if err := db.QueryRow(`SELECT count(*) FROM temporal_candidates`).Scan(&candidates); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if candidates != 1 || events != 3 {
		t.Fatalf("候选筛选影响事件或保留无关流量: %d/%d", candidates, events)
	}
	var ids []byte
	if err := db.QueryRow(`SELECT rules FROM temporal_candidates`).Scan(&ids); err != nil {
		t.Fatal(err)
	}
	var rules []string
	if err := json.Unmarshal(ids, &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0] != "base" {
		t.Fatalf("无关基础规则进入候选: %s", ids)
	}
	var count int
	if err := db.QueryRow(`SELECT sum(count) FROM alerts WHERE rule_id='unrelated'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("单事件告警受影响: %d %v", count, err)
	}
}

func TestProcessorSequenceUsesStrictEventTime(t *testing.T) {
	for _, tc := range []struct {
		name      string
		offset    time.Duration
		sameEvent bool
		want      int
	}{
		{name: "迟到前序", offset: -time.Second, want: 1},
		{name: "同时发生", offset: 0},
		{name: "反向顺序", offset: time.Second},
		{name: "一条匹配两步", sameEvent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, client, db := testProcessor(t)
			defer client.Close()
			defer db.Close()
			p.Temporal = temporalStoreFixtureWithRule(t, "id: ordered\nkind: sequence\nwithin: 1m\nrules: [base, unrelated]\nlevel: high\n")
			ctx := context.Background()
			asset, err := client.Asset.Create().SetHostname("sequence").SetGroupID(uuid.New()).Save(ctx)
			if err != nil {
				t.Fatal(err)
			}
			terminal := Envelope{Version: EnvelopeVersion, ID: uuid.New(), PartitionKey: asset.ID.String(), Timestamp: time.Now().UTC().Truncate(time.Microsecond), ClassUID: 1007, Source: "agent", AssetID: &asset.ID, Raw: json.RawMessage(`{"standalone":"yes"}`)}
			if tc.sameEvent {
				terminal.Raw = json.RawMessage(`{"marker":"yes","standalone":"yes"}`)
			}
			if err := p.Process(ctx, terminal); err != nil {
				t.Fatal(err)
			}
			if !tc.sameEvent {
				prior := terminal
				prior.ID = uuid.New()
				prior.Timestamp = terminal.Timestamp.Add(tc.offset)
				prior.Raw = json.RawMessage(`{"marker":"yes"}`)
				for range 2 {
					if err := p.Process(ctx, prior); err != nil {
						t.Fatal(err)
					}
				}
			}
			var n int
			if err := db.QueryRow(`SELECT count(*) FROM alerts WHERE rule_id='ordered'`).Scan(&n); err != nil || n != tc.want {
				t.Fatalf("序列告警数 %d 期望 %d: %v", n, tc.want, err)
			}
			if tc.want > 0 {
				var anchor uuid.UUID
				var count, severity int
				if err := db.QueryRow(`SELECT event_id,count,severity FROM alerts WHERE rule_id='ordered'`).Scan(&anchor, &count, &severity); err != nil {
					t.Fatal(err)
				}
				if anchor != terminal.ID || count != 1 || severity != 4 {
					t.Fatalf("序列告警错误: %s/%d/%d", anchor, count, severity)
				}
			}
		})
	}
}

func TestRuleArchiveRollsBackWithCandidate(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	ctx := context.Background()
	snapshot := temporalStoreFixtureWithRule(t, "id: archive-"+uuid.NewString()+"\nkind: event_count\nwithin: 1m\nrules: [base]\nthreshold: 2\n").Current()
	asset, err := client.Asset.Create().SetHostname("archive-rollback").SetGroupID(uuid.New()).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e := Envelope{Version: EnvelopeVersion, ID: uuid.New(), PartitionKey: asset.ID.String(), Timestamp: time.Now(), ClassUID: 1007, Source: "agent", AssetID: &asset.ID, Raw: json.RawMessage(`{"marker":"yes"}`)}
	if err := p.Process(ctx, e); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.Observe(ctx, tx, e.ID, []string{"base"}); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM temporal_rule_snapshots WHERE revision=$1)`, snapshot.Revision()).Scan(&exists); err != nil || exists {
		t.Fatalf("回滚留下了未使用规则归档: %v %v", exists, err)
	}
}
