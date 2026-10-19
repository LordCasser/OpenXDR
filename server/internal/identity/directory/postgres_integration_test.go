//go:build integration

package directory

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/testdb"
)

func TestDirectoryPersistence(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	group := client.Group.Create().SetName("directory").SaveX(ctx)
	source := Source{ID: uuid.New(), GroupID: group.ID, Kind: "keycloak", Authority: "https://example.invalid/realms/one"}
	for range 2 {
		if err := RegisterSource(ctx, db, source); err != nil {
			t.Fatal(err)
		}
	}
	wrong := source
	wrong.Authority += "other"
	if err := RegisterSource(ctx, db, wrong); !errors.Is(err, ErrSourceConflict) {
		t.Fatalf("来源重绑定: %v", err)
	}
	on, off := true, false
	start := time.Now().UTC().Add(-time.Hour)
	scan := Scan{Source: source, StartedAt: start, FinishedAt: start.Add(time.Minute), Accounts: []Account{{ExternalID: "one", Username: "same", Enabled: &on}, {ExternalID: "two", Username: "same", Enabled: nil}}}
	if err := SaveScan(ctx, db, scan); err != nil {
		t.Fatal(err)
	}
	if err := SaveScan(ctx, db, scan); !errors.Is(err, ErrStaleScan) {
		t.Fatalf("旧扫描重写: %v", err)
	}
	id, _ := source.AccountID("one")
	next := scan
	next.StartedAt = start.Add(2 * time.Minute)
	next.FinishedAt = start.Add(3 * time.Minute)
	next.Accounts = []Account{{ExternalID: "one", Username: "renamed", Enabled: &off}}
	if err := SaveScan(ctx, db, next); err != nil {
		t.Fatal(err)
	}
	var username string
	var enabled sql.NullBool
	var observed time.Time
	if err := db.QueryRowContext(ctx, `SELECT username,enabled,observed_at FROM identity_directory_accounts WHERE id=$1`, id).Scan(&username, &enabled, &observed); err != nil {
		t.Fatal(err)
	}
	if username != "renamed" || !enabled.Valid || enabled.Bool {
		t.Fatal("重命名或停用状态未同步")
	}
	if err := db.QueryRowContext(ctx, `SELECT enabled,observed_at FROM identity_directory_accounts WHERE source_id=$1 AND external_id='two'`, source.ID).Scan(&enabled, &observed); err != nil {
		t.Fatal(err)
	}
	if enabled.Valid || !observed.Equal(scan.FinishedAt.Truncate(time.Microsecond)) {
		t.Fatal("缺席账号被改写或未知状态被补造")
	}
	// 更换来源声明不能借已登记来源写入。
	bad := next
	bad.Source = wrong
	if err := SaveScan(ctx, db, bad); !errors.Is(err, ErrSourceConflict) {
		t.Fatalf("来源伪换: %v", err)
	}
	// 数据库在第二条写入失败时，第一条账号及同步游标也必须回滚。
	if _, err := db.ExecContext(ctx, `ALTER TABLE identity_directory_accounts ADD CONSTRAINT test_reject_name CHECK (username <> 'reject')`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db2, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
		if err == nil {
			defer db2.Close()
			db2.ExecContext(context.Background(), `ALTER TABLE identity_directory_accounts DROP CONSTRAINT IF EXISTS test_reject_name`)
		}
	})
	bad = next
	bad.StartedAt = start.Add(4 * time.Minute)
	bad.FinishedAt = start.Add(5 * time.Minute)
	bad.Accounts = []Account{{ExternalID: "one", Username: "should-rollback", Enabled: &on}, {ExternalID: "three", Username: "reject"}}
	if err := SaveScan(ctx, db, bad); err == nil {
		t.Fatal("故障注入未失败")
	}
	var last time.Time
	if err := db.QueryRowContext(ctx, `SELECT username FROM identity_directory_accounts WHERE id=$1`, id).Scan(&username); err != nil || username != "renamed" {
		t.Fatal("账号写入没有回滚")
	}
	if err := db.QueryRowContext(ctx, `SELECT last_started_at FROM identity_directory_sources WHERE id=$1`, source.ID).Scan(&last); err != nil || !last.Equal(next.StartedAt.Truncate(time.Microsecond)) {
		t.Fatal("游标没有回滚")
	}
	// 空枚举只前进观察时间，不删除既有账号。
	bad.Accounts = []Account{}
	if err := SaveScan(ctx, db, bad); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM identity_directory_accounts WHERE source_id=$1`, source.ID).Scan(&count); err != nil || count != 2 {
		t.Fatal("空枚举删除账号")
	}
	adSource := source
	adSource.ID = uuid.New()
	adSource.Kind = "ad"
	if err := RegisterSource(ctx, db, adSource); err != nil {
		t.Fatal(err)
	}
	adScan := Scan{Source: adSource, StartedAt: start, FinishedAt: start.Add(time.Minute), Accounts: []Account{{ExternalID: "guid", Username: "domain-user", WindowsSID: "S-1-5-21-1-2-3-1001"}}}
	if err := SaveScan(ctx, db, adScan); err != nil {
		t.Fatal(err)
	}
	var savedSID sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT windows_sid FROM identity_directory_accounts WHERE source_id=$1`, adSource.ID).Scan(&savedSID); err != nil || savedSID.String != adScan.Accounts[0].WindowsSID {
		t.Fatal("AD SID 未保存")
	}
	adScan.StartedAt = start.Add(2 * time.Minute)
	adScan.FinishedAt = start.Add(3 * time.Minute)
	adScan.Accounts[0].WindowsSID = ""
	if err := SaveScan(ctx, db, adScan); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT windows_sid FROM identity_directory_accounts WHERE source_id=$1`, adSource.ID).Scan(&savedSID); err != nil || savedSID.Valid {
		t.Fatal("新观察缺失 SID 却保留旧值")
	}
	client.Group.DeleteOneID(group.ID).ExecX(ctx)
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM identity_directory_accounts WHERE source_id=$1`, source.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("归组删除未清理目录")
	}
}
