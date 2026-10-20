//go:build integration

package schedule

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/testdb"
)

func TestPartialFanoutResumesOtherGroups(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Date(2026, 10, 17, 2, 5, 0, 0, time.UTC)
	a := db.Group.Create().SetName("a").SaveX(ctx)
	b := db.Group.Create().SetName("b").SaveX(ctx)
	task := db.Task.Create().SetID("daily").SetCreatedAt(now.Add(-time.Hour)).SetName("daily").SetPrompt("test").SetSchedule("CRON_TZ=UTC 0 2 * * *").SaveX(ctx)
	db.TaskRun.Create().SetTaskID(task.ID).SetGroupID(a.ID).SetStartedAt(now.Add(-4 * time.Minute)).SetStatus("failed").SaveX(ctx)
	s := &Scheduler{DB: db, start: now}
	dueA, err := s.due(ctx, task, a.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	dueB, err := s.due(ctx, task, b.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if !dueA.IsZero() || dueB.IsZero() {
		t.Fatalf("A 应跳过，B 应补跑: A=%v B=%v", dueA, dueB)
	}
	_, _, err = s.begin(ctx, task, b, "test", dueB)
	if err != nil {
		t.Fatal(err)
	}
	before := db.AgentSession.Query().CountX(ctx)
	_, _, err = s.begin(ctx, task, b, "test", dueB)
	if err == nil {
		t.Fatal("同组同一触发点重复创建")
	}
	if n := db.AgentSession.Query().CountX(ctx); n != before {
		t.Fatal("竞争失败遗留会话")
	}
}

func TestTaskCreatedAtMigratesExistingRows(t *testing.T) {
	ctx, db := testdb.New(t)
	db.Task.Create().SetID("legacy").SetName("旧任务").SetSchedule("0 2 * * *").SetPrompt("检查").SaveX(ctx)
	raw, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	// 模拟升级前已有任务的表，不能依赖仅作用于新 INSERT 的 Go 默认值。
	if _, err := raw.ExecContext(ctx, "ALTER TABLE tasks DROP COLUMN created_at"); err != nil {
		t.Fatal(err)
	}
	if err := db.Schema.Create(ctx, eventpart.SchemaOption); err != nil {
		t.Fatal(err)
	}
	if db.Task.GetX(ctx, "legacy").CreatedAt.IsZero() {
		t.Fatal("已有任务未回填创建时间")
	}
}
