//go:build integration

package directory

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/testdb"
)

func TestDirectoryMaintenanceFencesLateResults(t *testing.T) {
	ctx, c := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	group := c.Group.Create().SetName("maintenance").SaveX(ctx)
	source := Source{ID: uuid.New(), GroupID: group.ID, Kind: "ad", Authority: "ldaps://directory.invalid"}
	if err := RegisterSource(ctx, db, source); err != nil {
		t.Fatal(err)
	}
	insert := func(age time.Duration, status string) uuid.UUID {
		t.Helper()
		id := uuid.New()
		var finished any
		if status != "running" {
			finished = time.Now().Add(-age)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO identity_directory_runs(id,source_id,started_at,finished_at,status) VALUES($1,$2,$3,$4,$5)`, id, source.ID, time.Now().Add(-age), finished, status); err != nil {
			t.Fatal(err)
		}
		return id
	}
	old := insert(10*time.Minute, "running")
	fresh := insert(time.Minute, "running")
	scan := Scan{Source: source, StartedAt: time.Now().Add(-time.Minute), FinishedAt: time.Now(), Accounts: []Account{{ExternalID: "one", Username: "late"}}}
	// 即使维护尚未执行，超过数据库提交期限的运行也必须整体回滚。
	if err := finishRun(ctx, db, old, scan); err == nil {
		t.Fatal("过期运行仍可提交")
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM identity_directory_accounts WHERE source_id=$1`, source.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("过期结果没有回滚")
	}
	lock, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err := lock.ExecContext(ctx, `SELECT id FROM identity_directory_runs WHERE id=$1 FOR UPDATE`, old); err != nil {
		t.Fatal(err)
	}
	expired, _, err := MaintainRuns(ctx, db, 0)
	if err != nil || expired != 0 {
		t.Fatal("维护没有跳过持锁记录")
	}
	if err := lock.Rollback(); err != nil {
		t.Fatal(err)
	}
	expired, _, err = MaintainRuns(ctx, db, 0)
	if err != nil || expired != 1 {
		t.Fatalf("过期回收: %d %v", expired, err)
	}
	run, err := readRun(ctx, db, old)
	if err != nil || run.Status != "failed" || run.ErrorCode != "deadline_exceeded" {
		t.Fatal("过期状态错误")
	}
	if err := finishRun(ctx, db, old, scan); err == nil {
		t.Fatal("回收后迟到提交成功")
	}
	if err := finishRun(ctx, db, fresh, scan); err != nil {
		t.Fatal(err)
	}
	if _, err := failRun(db, run, "read_failed"); err == nil {
		t.Fatal("过期运行变成成功")
	}
	oldTerminal := insert(40*24*time.Hour, "failed")
	_, removed, err := MaintainRuns(ctx, db, 30*24*time.Hour)
	if err != nil || removed != 1 {
		t.Fatalf("历史清理: %d %v", removed, err)
	}
	if _, err := readRun(ctx, db, oldTerminal); err == nil {
		t.Fatal("过期历史未删除")
	}
	// 全部历史已久仍保留该来源最后一条。
	if _, err := db.ExecContext(ctx, `DELETE FROM identity_directory_runs WHERE source_id=$1`, source.ID); err != nil {
		t.Fatal(err)
	}
	latest := insert(40*24*time.Hour, "succeeded")
	_, removed, err = MaintainRuns(ctx, db, 30*24*time.Hour)
	if err != nil || removed != 0 {
		t.Fatal("删除了来源最后状态")
	}
	if _, err := readRun(ctx, db, latest); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO identity_directory_runs(id,source_id,started_at,finished_at,status)
 SELECT md5('directory-retention-'||g::text)::uuid,$1,now()-interval '50 days',now()-interval '50 days','failed'
 FROM generate_series(1,1001) g`, source.ID); err != nil {
		t.Fatal(err)
	}
	_, removed, err = MaintainRuns(ctx, db, 0)
	if err != nil || removed != 0 {
		t.Fatal("关闭历史删除未生效")
	}
	for _, want := range []int64{1000, 1} {
		_, removed, err = MaintainRuns(ctx, db, 30*24*time.Hour)
		if err != nil || removed != want {
			t.Fatalf("清理批次超限或遗漏: %d %v", removed, err)
		}
	}
}
