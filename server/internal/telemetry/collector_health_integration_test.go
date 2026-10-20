//go:build integration

package telemetry

import (
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"openxdr/server/internal/testdb"
)

// 只数在线、快照新鲜的主机；静默降级单独一个 silent=true 序列
func TestCollectorHealthMetric(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	snapshot := func(at time.Time, caps map[string]any) json.RawMessage {
		b, _ := json.Marshal(map[string]any{"receivedAt": at, "capabilities": caps})
		return b
	}
	silent := map[string]any{"path": "etw", "state": "degraded", "reason": "持续 5 分钟收不到进程事件"}
	for _, h := range []struct {
		name   string
		at     time.Time
		silent bool
		caps   map[string]any
	}{
		{"win1", now, false, map[string]any{"process": silent, "network": map[string]any{"path": "etw", "state": "active"}}},
		{"win2", now, false, map[string]any{"process": silent, "files": map[string]any{"path": "inotify", "state": "degraded"}}},
		{"stale", now.Add(-10 * time.Minute), false, map[string]any{"process": silent}},
		{"gone", now, true, map[string]any{"process": silent}},
	} {
		c := client.Asset.Create().SetHostname(h.name).SetAgentID(uuid.New()).SetLastSeen(now).
			SetCollectorHealth(snapshot(h.at, h.caps))
		if h.silent {
			c.SetSilentSince(now)
		}
		c.SaveX(ctx)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollectorHealth(db))
	want := `
# HELP openxdr_collector_capability_problem_hosts 采集能力降级或不可用的在线主机数；silent=true 表示通道开着却持续收不到事件（agent 活性检测判定）
# TYPE openxdr_collector_capability_problem_hosts gauge
openxdr_collector_capability_problem_hosts{capability="files",silent="false",state="degraded"} 1
openxdr_collector_capability_problem_hosts{capability="process",silent="true",state="degraded"} 2
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want)); err != nil {
		t.Fatal(err)
	}
}
