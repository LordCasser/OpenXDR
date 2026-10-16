//go:build integration

package commandgate

import (
	"context"
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
	cmd := "whoami"
	return fixture{ctx, db, &Gate{DB: db, Hub: hub, ApprovalTimeout: 2 * time.Second}, Request{UserID: actor.ID, GroupID: group.ID, Origin: "ai", Command: response.Request{Kind: "exec", AssetID: asset.ID, Cmd: &cmd, DryRun: true}}, admin, ch}
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
				if !cmd.DryRun || cmd.Cmd != "whoami" {
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
func TestPoliciesAndScope(t *testing.T) {
	f := setup(t)
	f.db.CommandPolicy.Create().SetGroupID(f.req.GroupID).SetOrigin(commandpolicy.OriginAi).SetMode(commandpolicy.ModeAllow).SetPattern("whoami").SaveX(f.ctx)
	if _, err := f.gate.Issue(f.ctx, f.req); err != nil {
		t.Fatal(err)
	}
	<-f.ch
	f.req.GroupID = uuid.New()
	if _, err := f.gate.Issue(f.ctx, f.req); err == nil {
		t.Fatal("跨组必须拒绝")
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
