//go:build integration

package commandgate

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/approval"
	"openxdr/server/ent/commandpolicy"
	"openxdr/server/ent/groupmember"
	"openxdr/server/internal/response"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	ctx   context.Context
	db    *ent.Client
	gate  *Gate
	req   Request
	admin *ent.User
	ch    chan *pb.Command
}

func setup(t *testing.T) fixture {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("test-group").SaveX(ctx)
	actor := db.User.Create().SetUsername("analyst").SetPasswordHash("unused").SetRole("analyst").SaveX(ctx)
	admin := db.User.Create().SetUsername("admin").SetPasswordHash("unused").SetRole("admin").SaveX(ctx)
	db.GroupMember.Create().SetGroupID(group.ID).SetUserID(actor.ID).SetRole("analyst").SaveX(ctx)
	agent := uuid.New()
	asset := db.Asset.Create().SetHostname("test").SetAgentID(agent).SetGroupID(group.ID).SaveX(ctx)
	hub := response.NewHub(db, true)
	ch := hub.Attach(agent)
	t.Cleanup(func() { hub.Detach(agent, ch) })
	// whoami 列入 AI 高风险名单，生命周期测试靠它挂起审批
	db.CommandPolicy.Create().SetGroupID(group.ID).SetOrigin(commandpolicy.OriginAi).SetMode(commandpolicy.ModeDeny).SetPattern(`\bwhoami\b`).SaveX(ctx)
	cmd := "id && whoami"
	return fixture{ctx, db, &Gate{DB: db, Hub: hub, ApprovalTimeout: 2 * time.Second}, Request{UserID: actor.ID, GroupID: group.ID, Origin: "ai", Command: response.Request{Kind: "exec", AssetID: asset.ID, Cmd: &cmd}}, admin, ch}
}
func waitApproval(t *testing.T, f fixture) *ent.Approval {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		a, err := f.db.Approval.Query().Where(approval.StatusEQ(approval.StatusPending)).Only(f.ctx)
		if err == nil {
			return a
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("未创建待审批记录")
	return nil
}
func assertNoCommand(t *testing.T, f fixture) {
	t.Helper()
	select {
	case cmd := <-f.ch:
		t.Fatalf("不应下发: %v", cmd)
	default:
	}
}
func TestApprovalLifecycle(t *testing.T) {
	for _, mode := range []string{"approve", "reject", "expire", "cancel", "revoke", "move"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			if mode == "expire" {
				f.gate.ApprovalTimeout = 80 * time.Millisecond
			}
			done := make(chan error, 1)
			go func() { _, err := f.gate.Issue(ctx, f.req); done <- err }()
			a := waitApproval(t, f)
			assertNoCommand(t, f)
			switch mode {
			case "cancel":
				cancel()
			case "expire":
			default:
				if mode == "revoke" {
					f.db.GroupMember.Delete().Where(groupmember.UserIDEQ(f.req.UserID)).ExecX(f.ctx)
				}
				if mode == "move" {
					f.db.Asset.UpdateOneID(f.req.Command.AssetID).ClearGroupID().ExecX(f.ctx)
				}
				if err := f.gate.Decide(f.ctx, a.ID, f.admin, mode != "reject"); err != nil {
					t.Fatal(err)
				}
				if err := f.gate.Decide(f.ctx, a.ID, f.admin, true); err == nil {
					t.Fatal("重复决定应拒绝")
				}
			}
			err := <-done
			if mode == "approve" {
				if err != nil {
					t.Fatal(err)
				}
				cmd := <-f.ch
				if cmd.Cmd != "id && whoami" {
					t.Fatalf("审批命令变形: %+v", cmd)
				}
			} else {
				if err == nil {
					t.Fatal("应该拒绝")
				}
				assertNoCommand(t, f)
			}
			a = f.db.Approval.GetX(f.ctx, a.ID)
			if a.Status == approval.StatusPending || a.Status == approval.StatusApproved {
				t.Fatalf("遗留可用审批 %s", a.Status)
			}
			if n := f.db.AuditLog.Query().CountX(f.ctx); n < 2 {
				t.Fatalf("审计缺失: %d", n)
			}
		})
	}
}

// 名单外的命令直接执行，不建审批也不通知。
func TestPoliciesAndScope(t *testing.T) {
	f := setup(t)
	notified := 0
	f.gate.Notify = func(context.Context, string, string, string) error { notified++; return nil }
	other := "uptime"
	f.req.Command.Cmd = &other
	if _, err := f.gate.Issue(f.ctx, f.req); err != nil {
		t.Fatal(err)
	}
	<-f.ch
	if n := f.db.Approval.Query().CountX(f.ctx); n != 0 || notified != 0 {
		t.Fatalf("名单外命令不应审批或通知：审批 %d 通知 %d", n, notified)
	}
	f.req.GroupID = uuid.New()
	if _, err := f.gate.Issue(f.ctx, f.req); err == nil {
		t.Fatal("跨组必须拒绝")
	}
	assertNoCommand(t, f)
}

// 命中名单挂起审批并通知一次；超时与驳回的说法都不能让模型以为该换写法。
func TestDenyNotifiesAndWording(t *testing.T) {
	f := setup(t)
	var texts []string
	f.gate.Notify = func(_ context.Context, title, text, path string) error {
		if path != "/approvals" || !strings.Contains(title, "AI") {
			t.Errorf("通知标题或链接不对：%q %q", title, path)
		}
		texts = append(texts, text)
		return errors.New("webhook 挂了也不影响等待")
	}
	f.gate.ApprovalTimeout = 80 * time.Millisecond
	_, err := f.gate.Issue(f.ctx, f.req)
	if err == nil || strings.Contains(err.Error(), "拒绝") || !strings.Contains(err.Error(), "等待组管理员批准") {
		t.Fatalf("超时说法不对：%v", err)
	}
	if len(texts) != 1 || !strings.Contains(texts[0], "test-group") || !strings.Contains(texts[0], "主机：test") ||
		!strings.Contains(texts[0], "analyst") || !strings.Contains(texts[0], "id && whoami") {
		t.Fatalf("应通知一次且带组、主机、发起人与命令：%q", texts)
	}
	assertNoCommand(t, f)

	f.gate.ApprovalTimeout = 2 * time.Second
	done := make(chan error, 1)
	go func() { _, err := f.gate.Issue(f.ctx, f.req); done <- err }()
	a := waitApproval(t, f)
	if err := f.gate.Decide(f.ctx, a.ID, f.admin, false); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil || !strings.Contains(err.Error(), "没有批准") {
		t.Fatalf("驳回说法不对：%v", err)
	}
	assertNoCommand(t, f)

	// 迁移前遗留的 allow 行一律按无效名单处理，宁可不执行
	f.db.CommandPolicy.Create().SetGroupID(f.req.GroupID).SetOrigin(commandpolicy.OriginAi).SetMode(commandpolicy.ModeAllow).SetPattern("uptime").SaveX(f.ctx)
	other := "uptime"
	f.req.Command.Cmd = &other
	if _, err := f.gate.Issue(f.ctx, f.req); err == nil {
		t.Fatal("allow 名单应报错")
	}
	assertNoCommand(t, f)
}
func TestHumanDenyPolicy(t *testing.T) {
	f := setup(t)
	f.req.Origin = "human"
	if _, err := f.gate.Issue(f.ctx, f.req); err != nil {
		t.Fatal(err)
	}
	<-f.ch
	f.db.CommandPolicy.Create().SetGroupID(f.req.GroupID).SetOrigin(commandpolicy.OriginHuman).SetMode(commandpolicy.ModeDeny).SetPattern("whoami").SaveX(f.ctx)
	f.gate.ApprovalTimeout = 50 * time.Millisecond
	if _, err := f.gate.Issue(f.ctx, f.req); err == nil || !strings.Contains(err.Error(), "超时") {
		t.Fatalf("预期审批超时: %v", err)
	}
	assertNoCommand(t, f)
}
func TestApprovalRequiresGroupAdmin(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan error, 1)
	go func() { _, err := f.gate.Issue(ctx, f.req); done <- err }()
	a := waitApproval(t, f)
	if err := f.gate.Decide(f.ctx, a.ID, f.db.User.GetX(f.ctx, f.req.UserID), true); err == nil {
		t.Fatal("analyst 不能批准")
	}
	cancel()
	<-done
	assertNoCommand(t, f)
}

func TestConcurrentDecision(t *testing.T) {
	f := setup(t)
	done := make(chan error, 1)
	go func() { _, err := f.gate.Issue(f.ctx, f.req); done <- err }()
	a := waitApproval(t, f)
	decided := make(chan error, 2)
	for range 2 {
		go func() { decided <- f.gate.Decide(f.ctx, a.ID, f.admin, true) }()
	}
	successes := 0
	for range 2 {
		if <-decided == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("批准成功次数 %d", successes)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-f.ch
	assertNoCommand(t, f)
}
