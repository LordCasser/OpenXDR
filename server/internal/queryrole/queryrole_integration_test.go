//go:build integration

package queryrole

import (
	"database/sql"
	"os"
	"testing"

	"github.com/google/uuid"

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
	client.Asset.Create().SetHostname("a1").SetGroupID(a.ID).SaveX(ctx)
	client.Asset.Create().SetHostname("b1").SetGroupID(b.ID).SaveX(ctx)

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
