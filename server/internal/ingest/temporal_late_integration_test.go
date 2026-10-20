//go:build integration

package ingest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/temporal"
)

// 迟到超过余量的事件照常入库并出单事件告警，但不在可能已被清理的窗口上做时序求值，缺口可见。
func TestTemporalLateEventRecordsGap(t *testing.T) {
	p, c, db := testProcessor(t)
	defer c.Close()
	defer db.Close()
	ctx := context.Background()
	p.Temporal = temporalStoreFixture(t)
	metrics := &capacityMetrics{}
	p.Metrics = metrics
	group := uuid.New()
	asset := c.Asset.Create().SetHostname("late").SetGroupID(group).SaveX(ctx)
	old := time.Now().UTC().Add(-temporal.LateGrace - time.Minute).Truncate(time.Microsecond)
	event := func(ts time.Time) Envelope {
		return Envelope{Version: EnvelopeVersion, ID: uuid.New(), PartitionKey: asset.ID.String(), Timestamp: ts, ClassUID: 1007, Source: "agent", AssetID: &asset.ID, Raw: json.RawMessage(`{"marker":"yes"}`)}
	}
	first, second := event(old), event(old.Add(time.Second))
	for _, e := range []Envelope{first, second, second} {
		if err := p.Process(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if len(metrics.reasons) != 2 || metrics.reasons[0] != "late" || metrics.reasons[1] != "late" {
		t.Fatalf("迟到缺口未逐条计数或重投重复计数: %v", metrics.reasons)
	}
	var found int
	if err := db.QueryRow(`SELECT count(*) FROM temporal_detections`).Scan(&found); err != nil || found != 0 {
		t.Fatal("迟到事件在残缺窗口上产生了命中")
	}
	if err := db.QueryRow(`SELECT count(*) FROM temporal_candidates`).Scan(&found); err != nil || found != 0 {
		t.Fatal("超出保留的迟到事件不应写入候选")
	}
	var reason string
	var lower int
	var storedGroup uuid.UUID
	if err := db.QueryRow(`SELECT reason,candidate_count_lower_bound,group_id FROM temporal_evaluation_gaps WHERE event_id=$1`, second.ID).Scan(&reason, &lower, &storedGroup); err != nil || reason != "late" || lower != 0 || storedGroup != group {
		t.Fatalf("迟到缺口记录错误: %s %d %v", reason, lower, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM alerts WHERE rule_id='base'`).Scan(&found); err != nil || found != 1 {
		t.Fatal("单事件检测被迟到缺口阻断")
	}
	// 余量内的迟到仍正常回看补齐。
	recent := time.Now().UTC().Add(-temporal.LateGrace + 10*time.Minute).Truncate(time.Microsecond)
	for _, e := range []Envelope{event(recent.Add(time.Second)), event(recent)} {
		if err := p.Process(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.QueryRow(`SELECT count(*) FROM temporal_detections`).Scan(&found); err != nil || found != 1 || len(metrics.reasons) != 2 {
		t.Fatalf("余量内迟到事件未正常求值: %d %v", found, metrics.reasons)
	}
}
