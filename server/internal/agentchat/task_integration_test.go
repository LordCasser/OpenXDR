//go:build integration

package agentchat

import (
	"context"
	"encoding/json"
	"testing"
	"time"

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
					if _, err := h(ctx, "report", json.RawMessage(`{"title":"日报","markdown":"# 正常"}`)); err != nil {
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
		})
	}
}
