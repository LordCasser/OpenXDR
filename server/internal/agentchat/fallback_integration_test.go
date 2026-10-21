//go:build integration

package agentchat

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"openxdr/server/ent/approval"
	"openxdr/server/ent/report"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/piruntime"
	"openxdr/server/internal/schedule"
	"openxdr/server/internal/testdb"
)

func emit(t *testing.T, ctx context.Context, o piruntime.Observer, message string) {
	t.Helper()
	if err := o(ctx, piruntime.Event{Type: "event", Event: json.RawMessage(`{"type":"message_end","message":` + message + `}`)}); err != nil {
		t.Errorf("记录消息失败：%v", err)
	}
}

const fallbackPrompt = "对本组每台主机巡检：\n1. 运维：磁盘与 inode 使用率\n2. 安全：新增账户与 sudo 权限\n报告结构照常。"

// 运行期限到了模型仍没交报告：平台用已执行的命令与结果整理保底报告，不含模型的话，会话记为成功并标 PartialNote
func TestRunTaskFallbackReport(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	host := db.Asset.Create().SetHostname("pve1").SetGroupID(group.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("task").SetGroupID(group.ID).SetTitle("每日主机巡检").
		SetInitiator(commandgate.SystemActor).SetModel("m").SaveX(ctx)
	db.Approval.Create().SetGroupID(group.ID).SetSessionID(session.ID).SetAssetID(host.ID).SetRequestedBy(commandgate.SystemActor).
		SetOrigin(approval.OriginAi).SetCmd("cat /etc/shadow").SetTimeoutMs(60000).SetExpiresAt(time.Now()).SetStatus(approval.StatusExpired).SaveX(ctx)
	calls := 0
	service := &Service{DB: db, Timeout: 2 * time.Second, Runtime: fakeRunner{func(ctx context.Context, r piruntime.Request, h piruntime.Handler, o piruntime.Observer) (*piruntime.Result, error) {
		calls++
		if calls == 1 {
			emit(t, ctx, o, `{"role":"assistant","content":[{"type":"thinking","thinking":"THINKING-MARK"},{"type":"text","text":"ANSWER-MARK"},`+
				`{"type":"toolCall","id":"c1","name":"bash","arguments":{"command":"xdr exec pve1 df -h"}},{"type":"toolCall","id":"c2","name":"read","arguments":{"path":"SKILL.md"}}]}`)
			emit(t, ctx, o, `{"role":"toolResult","toolCallId":"c1","toolName":"bash","isError":false,"content":[{"type":"text","text":"/dev/sda1 94G 25G 28% /"}]}`)
			emit(t, ctx, o, `{"role":"toolResult","toolCallId":"c2","toolName":"read","isError":false,"content":[{"type":"text","text":"skill 正文"}]}`)
			emit(t, ctx, o, `{"role":"assistant","content":[{"type":"toolCall","id":"c3","name":"bash","arguments":{"command":"xdr sql 'select 1 `+"```"+`'"}}]}`)
			emit(t, ctx, o, `{"role":"toolResult","toolCallId":"c3","toolName":"bash","isError":true,"content":[{"type":"text","text":"查询超时"}]}`)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		// 收尾时模型太慢，写到一半期限就到了
		emit(t, ctx, o, `{"role":"assistant","content":[{"type":"text","text":"WRAPUP-MARK"}]}`)
		<-ctx.Done()
		return nil, ctx.Err()
	}}}
	if err := service.RunTask(ctx, schedule.Job{Session: session, Prompt: fallbackPrompt, ApprovalTimeout: time.Minute}); err != nil || calls != 2 {
		t.Fatalf("超时有保底报告应算完成：%v，调用 %d 次", err, calls)
	}
	got := db.AgentSession.GetX(ctx, session.ID)
	if got.Status != "succeeded" || got.Error == nil || *got.Error != PartialNote {
		t.Errorf("会话应为 succeeded 并标保底：%s %v", got.Status, got.Error)
	}
	reports := db.Report.Query().Where(report.SessionIDEQ(session.ID)).AllX(ctx)
	if len(reports) != 1 {
		t.Fatalf("应有一份保底报告：%d", len(reports))
	}
	r := reports[0]
	if r.Level != "attention" || r.Title != "每日主机巡检" || !strings.Contains(r.Summary, "模型未在时限内完成") {
		t.Errorf("保底报告头不符：%s %s %s", r.Level, r.Title, r.Summary)
	}
	for _, want := range []string{"模型未在时限内完成，以下为平台根据已执行命令与查询结果整理", "## 结论", "## 需要人处理", "## 证据", "## 未验证",
		"xdr exec pve1 df -h", "/dev/sda1 94G", "结果（出错）", "查询超时", "pve1：`` cat /etc/shadow ``", "运维：磁盘与 inode 使用率", "安全：新增账户与 sudo 权限", "````"} {
		if !strings.Contains(r.Markdown, want) {
			t.Errorf("保底报告缺少 %q：\n%s", want, r.Markdown)
		}
	}
	for _, banned := range []string{"ANSWER-MARK", "THINKING-MARK", "WRAPUP-MARK", "skill 正文", "SKILL.md"} {
		if strings.Contains(r.Markdown, banned) || strings.Contains(r.Summary, banned) {
			t.Errorf("保底报告不应含模型的话或沙箱内文件 %q", banned)
		}
	}
}

// 模型交了报告：期限截掉报告之后的那一轮、或截止时报告正在提交，都算正常完成，不出保底报告
func TestRunTaskReportBeforeDeadline(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	db.Asset.Create().SetHostname("h").SetGroupID(group.ID).SaveX(ctx)
	const body = `{"title":"日报","summary":"正常","markdown":"## 结论\n正常\n## 需要人处理\n无\n## 未验证\n无","level":"ok"}`
	for _, c := range []struct {
		name string
		// 报告在期限前交，还是期限到了才提交（宽限内写完）
		late bool
	}{{"交完报告后期限到", false}, {"截止时正在提交报告", true}} {
		t.Run(c.name, func(t *testing.T) {
			session := db.AgentSession.Create().SetKind("task").SetGroupID(group.ID).SetTitle("日报").
				SetInitiator(commandgate.SystemActor).SetModel("m").SaveX(ctx)
			calls := 0
			service := &Service{DB: db, Timeout: 2 * time.Second, Runtime: fakeRunner{func(ctx context.Context, r piruntime.Request, h piruntime.Handler, o piruntime.Observer) (*piruntime.Result, error) {
				calls++
				if calls == 1 {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				if c.late {
					<-ctx.Done()
				}
				if _, err := h(ctx, "report", json.RawMessage(body)); err != nil {
					t.Errorf("报告应写入：%v", err)
				}
				<-ctx.Done()
				return nil, ctx.Err()
			}}}
			if err := service.RunTask(ctx, schedule.Job{Session: session, Prompt: fallbackPrompt, ApprovalTimeout: time.Minute}); err != nil {
				t.Fatalf("交了报告应算完成：%v", err)
			}
			got := db.AgentSession.GetX(ctx, session.ID)
			if got.Status != "succeeded" || got.Error != nil {
				t.Errorf("会话应正常完成：%s %v", got.Status, got.Error)
			}
			reports := db.Report.Query().Where(report.SessionIDEQ(session.ID)).AllX(ctx)
			if len(reports) != 1 || reports[0].Level != "ok" {
				t.Errorf("只应有模型交的那一份报告：%v", reports)
			}
		})
	}
}

// 停机或失去租约（取消，不是到期）不出保底报告：调度器记 interrupted 重跑
func TestRunTaskCanceledNoFallback(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	db.Asset.Create().SetHostname("h").SetGroupID(group.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("task").SetGroupID(group.ID).SetTitle("日报").
		SetInitiator(commandgate.SystemActor).SetModel("m").SaveX(ctx)
	run, stop := context.WithCancel(ctx)
	service := &Service{DB: db, Timeout: time.Minute, Runtime: fakeRunner{func(ctx context.Context, r piruntime.Request, h piruntime.Handler, o piruntime.Observer) (*piruntime.Result, error) {
		stop()
		<-ctx.Done()
		return nil, ctx.Err()
	}}}
	if err := service.RunTask(run, schedule.Job{Session: session, Prompt: fallbackPrompt, ApprovalTimeout: time.Minute}); err == nil {
		t.Fatal("取消应返回错误")
	}
	if got := db.AgentSession.GetX(ctx, session.ID); got.Status != "failed" {
		t.Errorf("会话应为 failed：%s", got.Status)
	}
	if n := db.Report.Query().Where(report.SessionIDEQ(session.ID)).CountX(ctx); n != 0 {
		t.Errorf("取消不应出保底报告：%d", n)
	}
}
