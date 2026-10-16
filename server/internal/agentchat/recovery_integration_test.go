//go:build integration

package agentchat

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/hook"
	"openxdr/server/internal/piruntime"
	"openxdr/server/internal/testdb"
)

func TestRecoverExpiredSessions(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	create := func(kind string, expires time.Time) *ent.AgentSession {
		b := db.AgentSession.Create().SetKind(kind).SetGroupID(group.ID).SetModel("m").SetInitiator("system").SetCreatedAt(now.Add(-time.Hour))
		if !expires.IsZero() {
			b.SetRunExpiresAt(expires)
		}
		return b.SaveX(ctx)
	}
	dead := create("chat", now.Add(-time.Minute))
	alive := create("chat", now.Add(time.Minute))
	task := create("task", now.Add(-time.Minute))
	legacy := create("chat", time.Time{})
	finished := create("task", time.Time{})
	recent := create("task", time.Time{})
	db.AgentSession.UpdateOneID(finished.ID).SetStatus("succeeded").SetFinishedAt(now.Add(-2 * time.Minute)).ExecX(ctx)
	db.AgentSession.UpdateOneID(recent.ID).SetStatus("succeeded").SetFinishedAt(now).ExecX(ctx)
	interrupted := db.TaskRun.Create().SetTaskID("task").SetGroupID(group.ID).SetSessionID(finished.ID).SaveX(ctx)
	finishing := db.TaskRun.Create().SetTaskID("task").SetGroupID(group.ID).SetSessionID(recent.ID).SaveX(ctx)
	run := db.TaskRun.Create().SetTaskID("task").SetGroupID(group.ID).SetSessionID(task.ID).SaveX(ctx)
	service := &Service{DB: db}
	if err := service.recoverExpired(ctx, now, time.Time{}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uuid.UUID{dead.ID, task.ID} {
		if got := db.AgentSession.GetX(ctx, id); got.Status != "failed" || got.FinishedAt == nil {
			t.Fatalf("未恢复: %+v", got)
		}
	}
	if db.AgentSession.GetX(ctx, alive.ID).Status != "running" || db.AgentSession.GetX(ctx, legacy.ID).Status != "running" {
		t.Fatal("误伤活跃或宽限期内会话")
	}
	if db.TaskRun.GetX(ctx, interrupted.ID).Status != "failed" || db.TaskRun.GetX(ctx, finishing.ID).Status != "running" {
		t.Fatal("未恢复中断收尾或误伤正常收尾")
	}
	if db.TaskRun.GetX(ctx, run.ID).Status != "failed" {
		t.Fatal("任务运行未一起恢复")
	}
	if err := service.recoverExpired(ctx, now, now); err != nil {
		t.Fatal(err)
	}
	if db.AgentSession.GetX(ctx, legacy.ID).Status != "failed" {
		t.Fatal("旧会话未恢复")
	}
	if db.AgentSession.GetX(ctx, alive.ID).Status != "running" {
		t.Fatal("误伤其他节点正常运行")
	}
}

func TestTitleFailureFinishesSession(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	u := db.User.Create().SetUsername("u").SetRole("admin").SetPasswordHash("x").SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetGroupID(g.ID).SetModel("m").SetInitiator("u").SetStatus("idle").SaveX(ctx)
	db.AgentSession.Use(func(next ent.Mutator) ent.Mutator {
		return hook.AgentSessionFunc(func(ctx context.Context, m *ent.AgentSessionMutation) (ent.Value, error) {
			if _, ok := m.Title(); ok {
				return nil, errors.New("模拟标题写入失败")
			}
			return next.Mutate(ctx, m)
		})
	})
	s := &Service{DB: db, Runtime: fakeRunner{func(context.Context, piruntime.Request, piruntime.Handler, piruntime.Observer) (*piruntime.Result, error) {
		t.Fatal("标题失败不能继续推理")
		return nil, nil
	}}}
	if _, err := s.Chat(ctx, session.ID, u, "标题", nil); err == nil {
		t.Fatal("应返回标题写入错误")
	}
	got := db.AgentSession.GetX(ctx, session.ID)
	if got.Status != "failed" || got.RunExpiresAt != nil {
		t.Fatalf("会话未收尾: %+v", got)
	}
}
