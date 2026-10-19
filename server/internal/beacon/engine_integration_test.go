//go:build integration

package beacon

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/testdb"
)

func conn(ctx context.Context, t *testing.T, c *ent.Client, asset uuid.UUID, at time.Time, ip, host, proc string, extra map[string]any) {
	t.Helper()
	raw := map[string]any{
		"process":         map[string]any{"name": proc},
		"dst_endpoint":    map[string]any{"ip": ip, "port": 443, "hostname": host},
		"connection_info": map[string]any{"direction": "outbound", "protocol_name": "tcp"},
	}
	for k, v := range extra {
		raw[k] = v
	}
	b, _ := json.Marshal(raw)
	c.Event.Create().SetTs(at).SetClassUID(4001).SetSource("agent").SetAssetID(asset).SetRaw(b).ExecX(ctx)
}

func every(from time.Time, n int, gap time.Duration, f func(time.Time)) {
	for i := 0; i < n; i++ {
		f(from.Add(time.Duration(i) * gap))
	}
}

// 首次上线回放历史只学不报；之后新冒出的心跳，接入满学习期的资产报、刚接入的不报；
// 平台指令、内网目的地、抖动大的不算；重启后回看同一段不重复告警
func TestBeaconEngine(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	now := time.Now().Truncate(time.Second)
	old := client.Asset.Create().SetHostname("old").SetFirstSeen(now.AddDate(0, 0, -30)).SaveX(ctx)
	fresh := client.Asset.Create().SetHostname("fresh").SetFirstSeen(now.Add(-24 * time.Hour)).SaveX(ctx)

	// 历史：老资产三天前起每 10 分钟连 grafana.com，首次上线时只进基线
	every(now.Add(-72*time.Hour), 30, 10*time.Minute, func(at time.Time) {
		conn(ctx, t, client, old.ID, at, "34.120.177.193", "grafana.com", "grafana", nil)
	})
	e := &Engine{DB: client, SQL: db, LearningPeriod: 7 * 24 * time.Hour, Window: 12 * time.Hour, Interval: time.Minute}
	if err := e.start(ctx, now); err != nil {
		t.Fatal(err)
	}
	if err := e.drain(ctx, now); err != nil {
		t.Fatal(err)
	}
	if n := client.BeaconBaseline.Query().CountX(ctx); n != 1 {
		t.Fatalf("历史规律外联应进基线，得到 %d", n)
	}
	if n := client.Alert.Query().CountX(ctx); n != 0 {
		t.Fatalf("首次回放不应告警，得到 %d", n)
	}

	// 之后：两台都冒出每 5 分钟一次的新心跳；另有平台指令、内网、抖动大的外联，以及老外联照常
	later := now.Add(time.Minute)
	every(later, 20, 5*time.Minute, func(at time.Time) {
		conn(ctx, t, client, old.ID, at, "45.9.148.10", "", "python3", nil)
		conn(ctx, t, client, fresh.ID, at, "45.9.148.10", "", "python3", nil)
		conn(ctx, t, client, old.ID, at, "45.9.148.11", "", "curl", map[string]any{"platform_command": map[string]any{"uid": uuid.NewString()}})
		conn(ctx, t, client, old.ID, at, "10.1.1.200", "", "node", nil)
		conn(ctx, t, client, old.ID, at, "34.120.177.193", "grafana.com", "grafana", nil)
	})
	jitter := []time.Duration{2, 9, 3, 11, 4, 8, 2, 12, 5, 9, 3, 10}
	at := later
	for _, m := range jitter {
		at = at.Add(m * time.Minute)
		conn(ctx, t, client, old.ID, at, "45.9.148.12", "", "wget", nil)
	}
	end := later.Add(2 * time.Hour)
	if err := e.drain(ctx, end); err != nil {
		t.Fatal(err)
	}
	alerts := client.Alert.Query().Where(alert.RuleIDEQ(sigma.RuleBeacon)).AllX(ctx)
	if len(alerts) != 1 || *alerts[0].AssetID != old.ID || alerts[0].Severity != 3 || alerts[0].Detail == nil || alerts[0].EventID == nil {
		t.Fatalf("应只有老资产的新心跳告警：%+v", alerts)
	}
	t.Log(*alerts[0].Detail)

	// 重启后从一个窗口之前接着看：基线挡住，不重复告警
	again := &Engine{DB: client, SQL: db, LearningPeriod: 7 * 24 * time.Hour, Window: 12 * time.Hour, Interval: time.Minute}
	if err := again.start(ctx, end); err != nil {
		t.Fatal(err)
	}
	if err := again.drain(ctx, end.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if n := client.Alert.Query().CountX(ctx); n != 1 {
		t.Fatalf("重启后不应重复告警，得到 %d", n)
	}
	if n := client.BeaconBaseline.Query().CountX(ctx); n != 3 {
		t.Fatalf("基线应有老外联与两台主机的新心跳，得到 %d", n)
	}
}
