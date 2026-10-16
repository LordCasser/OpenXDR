//go:build integration

package commandgate

import (
	"strings"
	"testing"
	"time"

	"openxdr/server/ent/approval"
	"openxdr/server/ent/auditlog"
	"openxdr/server/ent/commandpolicy"
)

// 系统身份只能在本组的任务会话里用；人不能冒用任务会话，系统也不能借用对话会话。
func TestSystemIdentity(t *testing.T) {
	f := setup(t)
	g := f.req.GroupID
	f.db.CommandPolicy.Create().SetGroupID(g).SetOrigin(commandpolicy.OriginAi).SetMode(commandpolicy.ModeAllow).SetPattern("whoami").SaveX(f.ctx)
	task := f.db.AgentSession.Create().SetKind("task").SetGroupID(g).SetInitiator(SystemActor).SetModel("m").SaveX(f.ctx)
	chat := f.db.AgentSession.Create().SetKind("chat").SetGroupID(g).SetInitiator("analyst").SetModel("m").SaveX(f.ctx)

	sys := f.req
	sys.System = true
	cases := map[string]Request{}
	noSession := sys
	cases["系统身份无会话"] = noSession
	onChat := sys
	onChat.SessionID = &chat.ID
	cases["系统身份借对话会话"] = onChat
	human := f.req
	human.SessionID = &task.ID
	cases["人冒用任务会话"] = human
	for name, req := range cases {
		if _, err := f.gate.Issue(f.ctx, req); err == nil {
			t.Errorf("%s 应被拒绝", name)
		}
	}
	assertNoCommand(t, f)
	// 审计记用户名而不是用户 ID，被拒的请求也一样留痕
	if n := f.db.AuditLog.Query().Where(auditlog.ActionEQ("exec_requested"), auditlog.UsernameEQ("analyst")).CountX(f.ctx); n != 1 {
		t.Errorf("人工请求应以用户名留痕 1 条，得到 %d", n)
	}

	ok := sys
	ok.SessionID = &task.ID
	cmd, err := f.gate.Issue(f.ctx, ok)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.IssuedBy != SystemActor {
		t.Errorf("issued_by 应为 system，得到 %s", cmd.IssuedBy)
	}
	<-f.ch

	// 名单外命令按任务自己的审批超时等待，超时即拒绝
	other := "id"
	ok.Command.Cmd = &other
	ok.ApprovalTimeout = 80 * time.Millisecond
	start := time.Now()
	_, err = f.gate.Issue(f.ctx, ok)
	if err == nil || !strings.Contains(err.Error(), "审批超时") {
		t.Fatalf("应审批超时，得到 %v", err)
	}
	if time.Since(start) > time.Second {
		t.Error("应按任务的审批超时而不是全局超时")
	}
	a := f.db.Approval.Query().OnlyX(f.ctx)
	if a.RequestedBy != SystemActor || a.Status != approval.StatusExpired {
		t.Errorf("审批记录不符：%s %s", a.RequestedBy, a.Status)
	}
	assertNoCommand(t, f)
}
