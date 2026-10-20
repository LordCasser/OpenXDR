//go:build integration

package main

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/temporal"
	"openxdr/server/internal/testdb"
)

// 从真实库按时间顺序读回事件做时序回测：只读事务，不写候选、命中或告警。
func TestTemporalBacktestReadsDatabase(t *testing.T) {
	ctx, c := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// 共享测试库里别的测试会留下同版本归档；清掉后才能确认回测本身没写
	if _, err := db.Exec(`DELETE FROM temporal_rule_snapshots`); err != nil {
		t.Fatal(err)
	}
	group := c.Group.Create().SetName("backtest").SaveX(ctx)
	var hosts []uuid.UUID
	for _, name := range []string{"bt-1", "bt-2", "bt-3"} {
		hosts = append(hosts, c.Asset.Create().SetHostname(name).SetOs("linux").SetGroupID(group.ID).SaveX(ctx).ID)
	}
	start := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Hour)
	// 跨小时分段：五次失败跨过整点，分段读取仍是同一个窗口
	var ids []uuid.UUID
	for i := range 5 {
		e := c.Event.Create().SetTs(start.Add(55*time.Minute + time.Duration(i)*2*time.Minute)).SetAssetID(hosts[i%3]).SetSource("agent").
			SetClassUID(3002).SetUsername("Operator").SetRaw(json.RawMessage(`{"activity_id":1,"status_id":2}`)).SaveX(ctx)
		ids = append(ids, e.ID)
	}
	// 不命中任何被引用基础规则的事件只计入扫描数，不成为候选
	c.Event.Create().SetTs(start.Add(time.Hour)).SetAssetID(hosts[0]).SetSource("agent").SetClassUID(1007).SetRaw(json.RawMessage(`{"process":{"cmd_line":"id"}}`)).SaveX(ctx)

	root := filepath.Join("..", "..", "..")
	store := &temporal.Store{}
	if err := store.Reload(filepath.Join(root, "rules"), filepath.Join(root, "temporal-rules")); err != nil {
		t.Fatal(err)
	}
	b := newTemporalBacktest(store.Current(), store.Rules(), 3)
	events := 0
	for segment := start; segment.Before(start.Add(3 * time.Hour)); segment = segment.Add(time.Hour) {
		n, _, err := b.scanTemporal(db, "", segment, segment.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		events += n
	}
	account := b.stats["temporal:linux-account-auth-burst"]
	if events != 6 || b.candidates != 5 || account.hits != 1 || account.entities["account:operator"] != 1 || len(account.samples) != 1 {
		t.Fatalf("回测结果错误: events=%d candidates=%d %+v", events, b.candidates, account)
	}
	for i, id := range account.samples[0] {
		if id != ids[i] {
			t.Fatalf("样例证据顺序错误: %v", account.samples[0])
		}
	}
	if b.stats["temporal:linux-auth-burst"].hits != 0 {
		t.Fatal("分布在三台主机的失败不应命中资产维度")
	}
	for _, table := range []string{"temporal_candidates", "temporal_detections", "temporal_rule_snapshots WHERE revision='" + store.Current().Revision() + "'", "alerts"} {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("回测写了库 %s: %d %v", table, n, err)
		}
	}
	// 完整入口：解析时间范围并输出报告
	t.Setenv("DATABASE_URL", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err := temporalMain(filepath.Join(root, "rules"), filepath.Join(root, "temporal-rules"), start.Format(time.RFC3339), start.Add(3*time.Hour).Format(time.RFC3339), 1, 3); err != nil {
		t.Fatal(err)
	}
	if err := temporalMain(filepath.Join(root, "rules"), filepath.Join(root, "temporal-rules"), start.Format(time.RFC3339), start.Format(time.RFC3339), 1, 3); err == nil {
		t.Fatal("空时间范围必须拒绝")
	}
}
