//go:build integration

package agentchat

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/piruntime"
	"openxdr/server/internal/testdb"
	"strings"
	"testing"
)

type fakeRunner struct {
	run func(context.Context, piruntime.Request, piruntime.Handler, piruntime.Observer) (*piruntime.Result, error)
}

func (f fakeRunner) Run(ctx context.Context, r piruntime.Request, h piruntime.Handler, o piruntime.Observer) (*piruntime.Result, error) {
	return f.run(ctx, r, h, o)
}
func TestSessionHistoryAndReports(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	user := db.User.Create().SetUsername("a").SetPasswordHash("unused").SetRole("admin").SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator(user.Username).SetModel("test").SetStatus("idle").SaveX(ctx)
	db.Asset.Create().SetHostname("本组主机").SetGroupID(group.ID).SaveX(ctx)
	otherGroup := db.Group.Create().SetName("other").SaveX(ctx)
	db.Asset.Create().SetHostname("其他组秘密主机").SetGroupID(otherGroup.ID).SaveX(ctx)
	calls := 0
	service := &Service{DB: db}
	service.Runtime = fakeRunner{func(ctx context.Context, r piruntime.Request, h piruntime.Handler, o piruntime.Observer) (*piruntime.Result, error) {
		calls++
		if !strings.Contains(r.SystemPrompt, "本组主机") || strings.Contains(r.SystemPrompt, "其他组秘密主机") {
			t.Fatal("资产上下文越界或缺失")
		}
		if len(r.Messages) != (calls-1)*2 {
			t.Fatalf("历史丢失或重复: %d", len(r.Messages))
		}
		for _, tool := range r.Tools {
			if tool.Name == "query" {
				t.Fatal("未配置只读身份不能开放 query")
			}
		}
		for _, message := range []string{`{"role":"user","content":"检查","timestamp":1}`, `{"role":"assistant","content":[{"type":"text","text":"完成"}],"stopReason":"stop"}`} {
			event := piruntime.Event{Type: "event", Event: json.RawMessage(`{"type":"message_end","message":` + message + `}`)}
			if err := o(ctx, event); err != nil {
				return nil, err
			}
		}
		if _, err := h(ctx, "report", json.RawMessage(`{"title":"报告","markdown":"# 无异常"}`)); err != nil {
			return nil, err
		}
		return &piruntime.Result{Response: "完成", StopReason: "stop"}, nil
	}}
	for range 2 {
		if _, err := service.Chat(ctx, session.ID, user, "检查", nil); err != nil {
			t.Fatal(err)
		}
	}
	if got := db.AgentSession.GetX(ctx, session.ID); got.Status != "idle" {
		t.Fatalf("状态 %s", got.Status)
	}
	if n := db.SessionMessage.Query().CountX(ctx); n != 4 {
		t.Fatal(n)
	}
	if n := db.Report.Query().CountX(ctx); n != 2 {
		t.Fatal(n)
	}
	other := db.User.Create().SetUsername("other").SetPasswordHash("unused").SetRole("admin").SaveX(ctx)
	if _, err := service.Chat(ctx, session.ID, other, "检查", nil); err == nil {
		t.Fatal("不能续写其他人的会话")
	}
}
func TestConcurrentSessionAndFailure(t *testing.T) {
	ctx, db := testdb.New(t)
	user := db.User.Create().SetUsername("a").SetPasswordHash("unused").SetRole("admin").SaveX(ctx)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator(user.Username).SetModel("test").SetStatus("idle").SaveX(ctx)
	started, release := make(chan struct{}), make(chan struct{})
	service := &Service{DB: db, Runtime: fakeRunner{func(context.Context, piruntime.Request, piruntime.Handler, piruntime.Observer) (*piruntime.Result, error) {
		close(started)
		<-release
		return nil, errors.New("测试失败")
	}}}
	done := make(chan error, 1)
	go func() { _, err := service.Chat(ctx, session.ID, user, "检查", nil); done <- err }()
	<-started
	if _, err := service.Chat(ctx, session.ID, user, "重复", nil); err == nil {
		t.Fatal("必须拒绝并发续写")
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("错误丢失")
	}
	if got := db.AgentSession.GetX(ctx, session.ID); got.Status != "failed" || got.Error == nil {
		t.Fatalf("失败终态缺失: %+v", got)
	}
}
func TestSessionGroupScope(t *testing.T) {
	ctx, db := testdb.New(t)
	user := db.User.Create().SetUsername("a").SetPasswordHash("unused").SetRole("analyst").SaveX(ctx)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator(user.Username).SetModel("test").SetStatus("idle").SaveX(ctx)
	service := &Service{DB: db}
	if _, err := service.Chat(ctx, session.ID, user, "检查", nil); err == nil {
		t.Fatal("非成员不得执行")
	}
	if _, err := service.tool(ctx, &ent.AgentSession{GroupID: uuid.New()}, user, "query", json.RawMessage(`{"sql":"select 1"}`)); err == nil {
		t.Fatal("无 DSN 必须拒绝")
	}
}
