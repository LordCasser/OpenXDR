//go:build integration

package ingest

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"testing"
	"time"
)

type capacityMetrics struct{ reasons []string }

func (*capacityMetrics) Processed(string, bool, int, time.Duration) {}
func (*capacityMetrics) Failed(string)                              {}
func (m *capacityMetrics) TemporalSkipped(reason string)            { m.reasons = append(m.reasons, reason) }

func TestTemporalCapacityPersistsGapWithoutBlockingRawEvents(t *testing.T) {
	p, c, db := testProcessor(t)
	defer c.Close()
	defer db.Close()
	ctx := context.Background()
	p.Temporal = temporalStoreFixture(t)
	metrics := &capacityMetrics{}
	p.Metrics = metrics
	group := uuid.New()
	asset := c.Asset.Create().SetHostname("capacity").SetGroupID(group).SaveX(ctx)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := db.Exec(`INSERT INTO temporal_rule_snapshots(revision,document) VALUES($1,$2::jsonb) ON CONFLICT DO NOTHING`, p.Temporal.Current().Revision(), string(p.Temporal.Current().Archive())); err != nil {
		t.Fatal(err)
	}
	// 直接准备完整候选窗口，不在测试里先触发一万个检测终点。
	_, err := db.ExecContext(ctx, `WITH seeds AS (
 INSERT INTO events(id,ts,class_uid,source,asset_id,raw)
 SELECT md5('temporal-capacity-'||n)::uuid,$1::timestamptz,1007,'agent',$2::uuid,'{"marker":"yes"}'::jsonb
 FROM generate_series(1,10000) n RETURNING id,ts,asset_id)
 INSERT INTO temporal_candidates(revision,event_id,asset_id,group_id,ts,rules)
 SELECT $3,id,asset_id,$4,ts,'["base"]'::jsonb FROM seeds`, now, asset.ID, p.Temporal.Current().Revision(), group)
	if err != nil {
		t.Fatal(err)
	}
	e := Envelope{Version: EnvelopeVersion, ID: uuid.New(), PartitionKey: asset.ID.String(), Timestamp: now, ClassUID: 1007, Source: "agent", AssetID: &asset.ID, Raw: json.RawMessage(`{"marker":"yes"}`)}
	// 缺口自身存储失败时仍需回滚，而非静默吞掉检测错误。
	if _, err := db.Exec(`ALTER TABLE temporal_evaluation_gaps ADD CONSTRAINT reject_gap_test CHECK (reason <> 'candidate_limit') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec(`ALTER TABLE temporal_evaluation_gaps DROP CONSTRAINT IF EXISTS reject_gap_test`) })
	if err := p.Process(ctx, e); err == nil {
		t.Fatal("缺口写入失败应回滚")
	}
	var found int
	if err := db.QueryRow(`SELECT count(*) FROM events WHERE id=$1`, e.ID).Scan(&found); err != nil || found != 0 || len(metrics.reasons) != 0 {
		t.Fatal("失败事务留下事件或成功指标")
	}
	if _, err := db.Exec(`ALTER TABLE temporal_evaluation_gaps DROP CONSTRAINT reject_gap_test`); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(ctx, e); err != nil {
		t.Fatal(err)
	}
	var reason string
	var lower int
	var storedGroup uuid.UUID
	if err := db.QueryRow(`SELECT reason,candidate_count_lower_bound,group_id FROM temporal_evaluation_gaps WHERE event_id=$1`, e.ID).Scan(&reason, &lower, &storedGroup); err != nil || reason != "candidate_limit" || lower != 10001 || storedGroup != group {
		t.Fatalf("缺口记录错误: %s %d %v", reason, lower, err)
	}
	if len(metrics.reasons) != 1 || metrics.reasons[0] != "candidate_limit" {
		t.Fatalf("重投重复计数或指标缺失: %v", metrics.reasons)
	}
	if err := db.QueryRow(`SELECT count(*) FROM temporal_detections`).Scan(&found); err != nil || found != 0 {
		t.Fatal("截断窗口制造了时序命中")
	}
	if err := db.QueryRow(`SELECT count(*) FROM alerts WHERE event_id=$1 AND rule_id='base'`, e.ID).Scan(&found); err != nil || found != 1 {
		t.Fatal("基础检测被容量缺口阻断")
	}
	// 后续事件仍正常入库；窗口之外的候选照常求值，不把历史缺口自动标成已补检。
	e.ID = uuid.New()
	e.Timestamp = now.Add(3 * time.Minute)
	e.Raw = json.RawMessage(`{"marker":"yes"}`)
	if err := p.Process(ctx, e); err != nil {
		t.Fatal(err)
	}
	e.ID = uuid.New()
	e.Timestamp = e.Timestamp.Add(time.Second)
	if err := p.Process(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM temporal_detections`).Scan(&found); err != nil || found != 1 {
		t.Fatal("新窗口未恢复检测")
	}
	if err := db.QueryRow(`SELECT count(*) FROM temporal_evaluation_gaps`).Scan(&found); err != nil || found != 1 {
		t.Fatal("历史缺口被误清除")
	}
}
