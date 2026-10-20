//go:build integration

package agentchat

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/report"
	"openxdr/server/ent/sessionmessage"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/piruntime"
	"openxdr/server/internal/schedule"
	"openxdr/server/internal/testdb"
)

// 任务会话：交了报告且正常结束才算成功；截断、没交报告、非任务会话都失败。
func TestRunTask(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	db.Asset.Create().SetHostname("h").SetGroupID(group.ID).SaveX(ctx)

	cases := []struct {
		name       string
		kind       string
		report     bool
		stop       string
		wantStatus string
	}{
		{"正常", "task", true, "stop", "succeeded"},
		{"截断", "task", true, "length", "failed"},
		{"没交报告", "task", false, "stop", "failed"},
		{"对话会话", "chat", true, "stop", "running"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			session := db.AgentSession.Create().SetKind(c.kind).SetGroupID(group.ID).
				SetInitiator(commandgate.SystemActor).SetModel("m").SaveX(ctx)
			service := &Service{DB: db, Runtime: fakeRunner{func(ctx context.Context, r piruntime.Request, h piruntime.Handler, o piruntime.Observer) (*piruntime.Result, error) {
				if r.Prompt != "巡检" || len(r.Messages) != 0 {
					t.Errorf("任务请求不符：%q %d", r.Prompt, len(r.Messages))
				}
				msg := `{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"好"}]}}`
				if err := o(ctx, piruntime.Event{Type: "event", Event: json.RawMessage(msg)}); err != nil {
					return nil, err
				}
				if c.report {
					// 级别只收 ok / attention / urgent；无异常的巡检交 ok，只存档不推送
					if _, err := h(ctx, "report", json.RawMessage(`{"title":"日报","markdown":"# 正常","level":"info"}`)); err == nil {
						t.Error("未知级别应被拒绝")
					}
					if _, err := h(ctx, "report", json.RawMessage(`{"title":"日报","markdown":"# 正常","level":"ok"}`)); err != nil {
						return nil, err
					}
				}
				return &piruntime.Result{StopReason: c.stop}, nil
			}}}
			err := service.RunTask(ctx, schedule.Job{Session: session, Prompt: "巡检", ApprovalTimeout: time.Minute})
			if (err == nil) != (c.wantStatus == "succeeded") {
				t.Errorf("返回值不符：%v", err)
			}
			if got := db.AgentSession.GetX(ctx, session.ID); got.Status != c.wantStatus {
				t.Errorf("会话状态应为 %s，得到 %s", c.wantStatus, got.Status)
			}
			for _, r := range db.Report.Query().Where(report.SessionIDEQ(session.ID)).AllX(ctx) {
				if r.Level != "ok" {
					t.Errorf("报告级别应为 ok，得到 %q", r.Level)
				}
			}
		})
	}
}

// 轮数耗尽：在同一会话上带全部历史续一次只给 report 的收尾，交了报告就算成功；收尾仍耗尽则失败。
func TestRunTaskWrapUp(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	db.Asset.Create().SetHostname("h").SetGroupID(group.ID).SaveX(ctx)
	for _, c := range []struct {
		name, wrapStop, wantStatus string
	}{{"收尾成功", "stop", "succeeded"}, {"收尾仍耗尽", "max_turns", "failed"}} {
		t.Run(c.name, func(t *testing.T) {
			session := db.AgentSession.Create().SetKind("task").SetGroupID(group.ID).
				SetInitiator(commandgate.SystemActor).SetModel("m").SaveX(ctx)
			calls := 0
			service := &Service{DB: db, Runtime: fakeRunner{func(ctx context.Context, r piruntime.Request, h piruntime.Handler, o piruntime.Observer) (*piruntime.Result, error) {
				calls++
				msg := `{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"好"}]}}`
				if err := o(ctx, piruntime.Event{Type: "event", Event: json.RawMessage(msg)}); err != nil {
					return nil, err
				}
				if calls == 1 {
					return &piruntime.Result{StopReason: "max_turns"}, nil
				}
				if len(r.Tools) != 1 || r.Tools[0].Name != "report" || r.MaxTurns != wrapUpTurns || len(r.Messages) != 1 || !strings.Contains(r.Prompt, "report") {
					t.Errorf("收尾请求不符：工具 %v 轮数 %d 历史 %d 提示 %q", r.Tools, r.MaxTurns, len(r.Messages), r.Prompt)
				}
				if _, err := h(ctx, "report", json.RawMessage(`{"title":"日报","markdown":"# 部分未验证"}`)); err != nil {
					return nil, err
				}
				return &piruntime.Result{StopReason: c.wrapStop}, nil
			}}}
			err := service.RunTask(ctx, schedule.Job{Session: session, Prompt: "巡检", ApprovalTimeout: time.Minute})
			if (err == nil) != (c.wantStatus == "succeeded") || calls != 2 {
				t.Errorf("返回值不符：%v，调用 %d 次", err, calls)
			}
			if got := db.AgentSession.GetX(ctx, session.ID); got.Status != c.wantStatus {
				t.Errorf("会话状态应为 %s，得到 %s", c.wantStatus, got.Status)
			}
			seqs := db.SessionMessage.Query().Where(sessionmessage.SessionIDEQ(session.ID)).Order(ent.Asc(sessionmessage.FieldSeq)).Select(sessionmessage.FieldSeq).IntsX(ctx)
			if len(seqs) != 2 || seqs[0] != 1 || seqs[1] != 2 {
				t.Errorf("收尾消息应接着编号入库：%v", seqs)
			}
			if n := db.Report.Query().Where(report.SessionIDEQ(session.ID)).CountX(ctx); n != 1 {
				t.Errorf("报告应保存 1 份，得到 %d", n)
			}
		})
	}
}

// 调查阶段到点被截停：半截的工具调用补上结果，留出的收尾时间里交了报告就算成功，不再整轮失败
func TestRunTaskTimeoutWrapUp(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	db.Asset.Create().SetHostname("h").SetGroupID(group.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("task").SetGroupID(group.ID).
		SetInitiator(commandgate.SystemActor).SetModel("m").SaveX(ctx)
	calls := 0
	service := &Service{DB: db, Timeout: 2 * time.Second, Runtime: fakeRunner{func(ctx context.Context, r piruntime.Request, h piruntime.Handler, o piruntime.Observer) (*piruntime.Result, error) {
		calls++
		if calls == 1 {
			msg := `{"type":"message_end","message":{"role":"assistant","content":[{"type":"toolCall","id":"c1","name":"bash","arguments":{"command":"sleep 999"}}]}}`
			if err := o(ctx, piruntime.Event{Type: "event", Event: json.RawMessage(msg)}); err != nil {
				return nil, err
			}
			<-ctx.Done()
			return nil, fmt.Errorf("记录 Pi 事件失败: %w", ctx.Err())
		}
		if ctx.Err() != nil {
			t.Errorf("收尾时应还有剩余时间：%v", ctx.Err())
		}
		if !strings.Contains(r.Prompt, "运行时间已用完") || len(r.Tools) != 1 || r.Tools[0].Name != "report" || len(r.Messages) != 2 {
			t.Errorf("收尾请求不符：提示 %q 工具 %v 历史 %d", r.Prompt, r.Tools, len(r.Messages))
		}
		if _, err := h(ctx, "report", json.RawMessage(`{"title":"日报","markdown":"# 超时，部分未验证"}`)); err != nil {
			return nil, err
		}
		return &piruntime.Result{StopReason: "stop"}, nil
	}}}
	if err := service.RunTask(ctx, schedule.Job{Session: session, Prompt: "巡检", ApprovalTimeout: time.Minute}); err != nil || calls != 2 {
		t.Fatalf("超时应收尾成功：%v，调用 %d 次", err, calls)
	}
	if got := db.AgentSession.GetX(ctx, session.ID); got.Status != "succeeded" {
		t.Errorf("会话状态应为 succeeded，得到 %s", got.Status)
	}
	roles := db.SessionMessage.Query().Where(sessionmessage.SessionIDEQ(session.ID)).Order(ent.Asc(sessionmessage.FieldSeq)).Select(sessionmessage.FieldRole).StringsX(ctx)
	if len(roles) != 2 || roles[1] != "toolResult" {
		t.Errorf("被截停的工具调用应补上结果：%v", roles)
	}
}
