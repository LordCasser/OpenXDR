//go:build integration

package queryrole

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
)

// 自动开通的身份只看得到本组资产、读不到基表；重复开通不换密码；删组后账号不复存在。
func TestEnsureIsolatesGroupAndDrops(t *testing.T) {
	ctx, client := testdb.New(t)
	dsn := os.Getenv("INTEGRATION_DATABASE_URL")
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	a := client.Group.Create().SetName("a").SaveX(ctx)
	b := client.Group.Create().SetName("b").SaveX(ctx)
	a1 := client.Asset.Create().SetHostname("a1").SetGroupID(a.ID).SaveX(ctx)
	b1 := client.Asset.Create().SetHostname("b1").SetGroupID(b.ID).SaveX(ctx)
	// 新视图的两组数据：每张表各给 a、b 一份，只读身份只能看到 a 的
	now := time.Now()
	for _, x := range []struct {
		group uuid.UUID
		asset *ent.Asset
		ip    string
	}{{a.ID, a1, "203.0.113.1"}, {b.ID, b1, "198.51.100.1"}} {
		client.Finding.Create().SetGroupID(x.group).SetAssetID(x.asset.ID).SetKey("k").SetTitle("t").SaveX(ctx)
		client.Memory.Create().SetGroupID(x.group).SetContent("m").SetSource("human").SetAuthor("u").SaveX(ctx)
		client.Suppression.Create().SetRuleID("r").SetAssetID(x.asset.ID).SaveX(ctx)
		client.AssetLink.Create().SetSrcIP("10.0.0.1").SetSrcAssetID(x.asset.ID).SetDstIP(x.ip).SetDstPort(443).SetProto("tcp").
			SetCount(1).SetFirstSeen(now).SetLastSeen(now).SaveX(ctx)
		client.IPInfo.Create().SetIP(x.ip).SaveX(ctx)
		client.Report.Create().SetSessionID(uuid.New()).SetGroupID(x.group).SetTitle("r").SetMarkdown("m").SaveX(ctx)
	}
	client.Suppression.Create().SetRuleID("global").SaveX(ctx) // 全局抑制谁的视图里都不该有

	static := uuid.New()
	p := &Provisioner{DB: db, Client: client, BaseDSN: dsn, Static: map[uuid.UUID]string{static: "postgres://manual"}}
	if p.URL(ctx, a.ID) != "" {
		t.Fatal("未开通时应返回空")
	}
	if err := p.Ensure(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	first := p.URL(ctx, a.ID)
	if err := p.Ensure(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if again := p.URL(ctx, a.ID); first == "" || again != first {
		t.Fatalf("重复开通不应换密码：%q → %q", first, again)
	}
	if p.URL(ctx, static) != "postgres://manual" {
		t.Error("手工配置的身份应优先")
	}

	ro, err := sql.Open("pgx", first)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ro.Close() })
	var host string
	var n int
	if err := ro.QueryRowContext(ctx, `SELECT count(*), min(hostname) FROM assets`).Scan(&n, &host); err != nil {
		t.Fatal(err)
	}
	if n != 1 || host != "a1" {
		t.Errorf("只应看到本组资产 a1，实际 %d 条 %q", n, host)
	}
	for view, want := range map[string]string{
		"findings": "1", "memories": "1", "suppressions": "1", "asset_links": "1", "reports": "1",
		"ip_infos": "203.0.113.1",
	} {
		var got string
		q := `SELECT count(*)::text FROM ` + view
		if view == "ip_infos" {
			q = `SELECT string_agg(ip, ',') FROM ip_infos`
		}
		if err := ro.QueryRowContext(ctx, q).Scan(&got); err != nil || got != want {
			t.Errorf("%s 只应看到本组的数据：得到 %q，%v", view, got, err)
		}
	}
	if err := ro.QueryRowContext(ctx, `SELECT count(*) FROM public.assets`).Scan(&n); err == nil {
		t.Error("不应能读业务基表")
	}
	var readOnly string
	if err := ro.QueryRowContext(ctx, `SHOW default_transaction_read_only`).Scan(&readOnly); err != nil || readOnly != "on" {
		t.Errorf("应默认只读，实际 %q %v", readOnly, err)
	}
	ro.Close()

	if err := p.Drop(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := p.Drop(ctx, a.ID); err != nil {
		t.Fatalf("重复回收应无害：%v", err)
	}
	gone, _ := sql.Open("pgx", first)
	defer gone.Close()
	if err := gone.PingContext(ctx); err == nil {
		t.Error("回收后不应还能登录")
	}
}

// 删遗留 dry_run 列：旧版组视图挡着时报错不删，视图重建后删干净；重复执行无害，组视图照常可查。
func TestDropDryRunAfterViewRebuild(t *testing.T) {
	ctx, client := testdb.New(t)
	dsn := os.Getenv("INTEGRATION_DATABASE_URL")
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	g := client.Group.Create().SetName("g").SaveX(ctx)
	a := client.Asset.Create().SetHostname("g1").SetGroupID(g.ID).SaveX(ctx)
	p := &Provisioner{DB: db, Client: client, BaseDSN: dsn}
	t.Cleanup(func() { p.Drop(ctx, g.ID) })
	if err := p.Ensure(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	// 模拟升级前：四张表带 dry_run 列，组视图还是旧版定义
	schema, _ := names(g.ID)
	for _, stmt := range []string{
		`ALTER TABLE commands ADD COLUMN IF NOT EXISTS dry_run boolean NOT NULL DEFAULT true`,
		`ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS dry_run boolean NOT NULL DEFAULT true`,
		`ALTER TABLE approvals ADD COLUMN IF NOT EXISTS dry_run boolean NOT NULL DEFAULT true`,
		`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS dry_run boolean NOT NULL DEFAULT true`,
		`DROP VIEW ` + schema + `.commands`,
		`CREATE VIEW ` + schema + `.commands AS SELECT id, status, dry_run FROM public.commands`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := DropDryRun(ctx, db); err == nil {
		t.Fatal("旧版视图还引用 commands.dry_run 时应报错")
	}

	if err := p.Ensure(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := DropDryRun(ctx, db); err != nil {
			t.Fatalf("视图重建后应能删列且可重复执行：%v", err)
		}
	}
	var left int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns
  WHERE table_schema = current_schema() AND column_name = 'dry_run'`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("dry_run 列应全部删除，剩 %d %v", left, err)
	}

	client.Command.Create().SetKind("exec").SetAssetID(a.ID).SetIssuedBy("admin").SaveX(ctx)
	ro, err := sql.Open("pgx", p.URL(ctx, g.ID))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ro.Close() })
	var n int
	if err := ro.QueryRowContext(ctx, `SELECT count(*) FROM commands`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("删列后组视图应照常可查：%d %v", n, err)
	}
}
