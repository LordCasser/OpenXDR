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

func sensorRaw(at time.Time, state string, alive int) json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"receivedAt": at, "workers": 2, "workersAlive": alive,
		"capabilities": map[string]any{"capture": map[string]string{"path": "afpacket:eth0", "state": state}},
	})
	return b
}

// 探针抓包降级、停更（失联）走「主机采集异常」通知，与 agent 的问题签名分开记：
// agent 正常不会把探针问题报成恢复，探针恢复也不清 agent 的标记。
func TestSensorHealthNotify(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()
	gw := client.Asset.Create().SetHostname("gw01").SetAgentID(uuid.New()).SetLastSeen(now).
		SetHealthProblem("cap:network:unavailable").
		SetSensorHealth(sensorRaw(now, "degraded", 2)).SaveX(ctx)

	var titles, bodies []string
	w := &Watcher{DB: client, Notify: func(_ context.Context, title, body, _ string) error {
		titles, bodies = append(titles, title), append(bodies, body)
		return nil
	}}
	sweep := func(at time.Time) {
		t.Helper()
		if err := w.sweepSensorHealth(ctx, at); err != nil {
			t.Fatal(err)
		}
	}
	sweep(now)
	sweep(now.Add(time.Minute))
	if len(titles) != 1 || titles[0] != "1 台主机采集异常" || !strings.Contains(bodies[0], "gw01：流量抓包降级（afpacket:eth0）：近一小时丢包") {
		t.Fatalf("丢包降级应只通知一次：%v %v", titles, bodies)
	}

	client.Asset.UpdateOne(gw).SetSensorHealth(sensorRaw(now, "degraded", 1)).ExecX(ctx)
	sweep(now.Add(2 * time.Minute))
	if len(titles) != 1 {
		t.Fatalf("同一问题换了说法不应再通知：%v", titles)
	}

	// 快照停更超过 5 分钟就是失联
	sweep(now.Add(10 * time.Minute))
	if len(titles) != 2 || !strings.Contains(bodies[1], "流量探针失联") {
		t.Fatalf("停更应报失联：%v %v", titles, bodies)
	}

	client.Asset.UpdateOne(gw).SetSensorHealth(sensorRaw(now.Add(11*time.Minute), "active", 2)).ExecX(ctx)
	sweep(now.Add(11 * time.Minute))
	got := client.Asset.GetX(ctx, gw.ID)
	if len(titles) != 3 || titles[2] != "1 台主机采集恢复正常" || got.SensorProblem != nil {
		t.Fatalf("恢复应通知并清探针标记：%v", titles)
	}
	if got.HealthProblem == nil || *got.HealthProblem != "cap:network:unavailable" {
		t.Fatal("探针恢复不应清 agent 的问题标记")
	}
}
