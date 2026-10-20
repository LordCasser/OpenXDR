//go:build integration

package liveness

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/testdb"
)

func snapshot(at time.Time, dropped int64, network string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"receivedAt": at, "droppedEvents": dropped, "writeBlocked": false,
		"capabilities": map[string]any{
			"process": map[string]string{"path": "ebpf", "state": "active"},
			"network": map[string]string{"path": "ebpf-not-built", "state": network},
		},
	})
	return b
}

// 采集降级通知一次、恢复通知一次；丢事件超阈值后一小时内不反复；agent 重启计数归零不误报；
// 快照过期与已失联的不评估；推送失败不落标记
func TestHealthNotify(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()
	a := client.Asset.Create().SetHostname("pve2").SetAgentID(uuid.New()).SetLastSeen(now).
		SetCollectorHealth(snapshot(now, 0, "unavailable")).SaveX(ctx)
	client.Asset.Create().SetHostname("stale").SetAgentID(uuid.New()).SetLastSeen(now).
		SetCollectorHealth(snapshot(now.Add(-10*time.Minute), 0, "unavailable")).SaveX(ctx)
	client.Asset.Create().SetHostname("gone").SetAgentID(uuid.New()).SetLastSeen(now).SetSilentSince(now).
		SetCollectorHealth(snapshot(now, 0, "unavailable")).SaveX(ctx)

	var titles, bodies []string
	fail := true
	w := &Watcher{DB: client, DropAlert: 1000, Notify: func(_ context.Context, title, body, _ string) error {
		if fail {
			return context.DeadlineExceeded
		}
		titles, bodies = append(titles, title), append(bodies, body)
		return nil
	}}
	sweep := func(at time.Time) {
		t.Helper()
		if err := w.sweepHealth(ctx, at); err != nil {
			t.Fatal(err)
		}
	}
	set := func(at time.Time, dropped int64, network string) {
		client.Asset.UpdateOne(a).SetCollectorHealth(snapshot(at, dropped, network)).ExecX(ctx)
	}

	if err := w.sweepHealth(ctx, now); err == nil || client.Asset.GetX(ctx, a.ID).HealthProblem != nil {
		t.Fatal("推送失败应返回错误且不落标记")
	}
	fail = false
	sweep(now)
	sweep(now.Add(time.Minute))
	if len(titles) != 1 || titles[0] != "1 台主机采集异常" || !strings.Contains(bodies[0], "pve2：网络采集不可用（ebpf-not-built）") {
		t.Fatalf("网络采集不可用应只通知一次、只报 pve2: %v %v", titles, bodies)
	}

	set(now, 0, "active")
	sweep(now.Add(2 * time.Minute))
	if len(titles) != 2 || titles[1] != "1 台主机采集恢复正常" || client.Asset.GetX(ctx, a.ID).HealthProblem != nil {
		t.Fatalf("恢复应通知并清标记: %v", titles)
	}

	// 一轮丢了 5000 条：通知；随后不再增长，一小时内不反复、不报恢复
	set(now.Add(3*time.Minute), 5000, "active")
	sweep(now.Add(3 * time.Minute))
	if len(titles) != 3 || !strings.Contains(bodies[2], "本轮丢弃 5000 条事件") {
		t.Fatalf("超阈值丢事件应通知: %v %v", titles, bodies)
	}
	set(now.Add(30*time.Minute), 5000, "active")
	sweep(now.Add(30 * time.Minute))
	// agent 重启，累计数归零后又涨了一点：不算新的异常
	set(now.Add(40*time.Minute), 20, "active")
	sweep(now.Add(40 * time.Minute))
	if len(titles) != 3 {
		t.Fatalf("一小时内不应反复通知: %v", titles)
	}
	set(now.Add(65*time.Minute), 30, "active")
	sweep(now.Add(65 * time.Minute))
	if len(titles) != 4 || titles[3] != "1 台主机采集恢复正常" {
		t.Fatalf("丢事件停了一小时应报恢复: %v", titles)
	}
}
