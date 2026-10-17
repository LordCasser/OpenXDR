//go:build integration

package response

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

// Issue 三道闸门：能力未启用、资产无 agent、agent 未连接——三种都不得真执行。
func TestIssueGateways(t *testing.T) {
	ctx, client := testdb.New(t)

	agentID := uuid.New()
	asset, err := client.Asset.Create().
		SetHostname("victim").SetAgentID(agentID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// 闸门一：RESPONSE_ENABLED=false，一律拒绝，且不落库
	off := NewHub(client, false)
	if _, err := off.Issue(ctx, Request{AssetID: asset.ID, Kind: "isolate_host", IssuedBy: "admin"}); err == nil {
		t.Fatal("能力未启用时 Issue 应拒绝")
	}
	if n, _ := client.Command.Query().Count(ctx); n != 0 {
		t.Fatalf("被拒绝的指令不应落库，实际 %d 条", n)
	}

	// 闸门二：资产没有 agent，无法下发
	noAgent, err := client.Asset.Create().SetHostname("orphan").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	on := NewHub(client, true)
	if _, err := on.Issue(ctx, Request{AssetID: noAgent.ID, Kind: "kill_process", IssuedBy: "admin"}); err == nil {
		t.Fatal("无 agent 的资产应拒绝下发")
	}

	// 闸门三：agent 在线但未连接指令通道（无 Router）→ 记 failed 而不是假装成功
	cmd, err := on.Issue(ctx, Request{AssetID: asset.ID, Kind: "isolate_host", IssuedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := client.Command.Get(ctx, cmd.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "failed" {
		t.Errorf("agent 未连接应记 failed，实际 %q", stored.Status)
	}
	if stored.CompletedAt == nil {
		t.Error("failed 指令应记录完成时间")
	}
}

// exec 全链路：下发带命令行、回执落输出；非 exec 回执不写输出字段。
func TestExecRoundTrip(t *testing.T) {
	ctx, client := testdb.New(t)

	agentID := uuid.New()
	asset, err := client.Asset.Create().SetHostname("web-01").SetAgentID(agentID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hub := NewHub(client, true)
	ch := hub.Attach(agentID)

	line := "uname -a"
	cmd, err := hub.Issue(ctx, Request{AssetID: asset.ID, Kind: "exec", Cmd: &line, TimeoutMS: 5000, IssuedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	sent := <-ch
	if sent.Kind != pb.CommandKind_EXEC || sent.Cmd != line || sent.TimeoutMs != 5000 {
		t.Fatalf("下发内容不符: %+v", sent)
	}
	if replay := hub.ToProto(cmd); replay.Cmd != line || replay.TimeoutMs != 5000 {
		t.Fatalf("序列化丢了命令行: %+v", replay)
	}

	hub.Complete(ctx, agentID, &pb.CommandResult{
		AgentId: agentID.String(), CommandId: cmd.ID.String(),
		Status: pb.CommandResult_SUCCEEDED, Detail: "退出码 2",
		ExitCode: 2, Stdout: "Linux", Stderr: "warn", Truncated: true,
	})
	got, err := client.Command.Get(ctx, cmd.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "succeeded" || got.ExitCode == nil || *got.ExitCode != 2 ||
		*got.Stdout != "Linux" || *got.Stderr != "warn" || !got.Truncated {
		t.Fatalf("exec 结果未完整回写: %+v", got)
	}

	kill, err := hub.Issue(ctx, Request{AssetID: asset.ID, Kind: "kill_process", PID: 1, IssuedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	<-ch
	hub.Complete(ctx, agentID, &pb.CommandResult{CommandId: kill.ID.String(), Status: pb.CommandResult_SUCCEEDED, Detail: "已结束 pid 1"})
	if got, _ := client.Command.Get(ctx, kill.ID); got.ExitCode != nil {
		t.Errorf("非 exec 指令不应写退出码: %v", *got.ExitCode)
	}
}

// 回执归属只相信已验证的流身份，不能伪造消息内 AgentId 污染别的资产。
func TestResultBoundToAgentAndFirstTerminal(t *testing.T) {
	ctx, db := testdb.New(t)
	agentID, other := uuid.New(), uuid.New()
	a := db.Asset.Create().SetHostname("bound").SetAgentID(agentID).SaveX(ctx)
	h := NewHub(db, true)
	ch := h.Attach(agentID)
	line := "whoami"
	cmd, err := h.Issue(ctx, Request{AssetID: a.ID, Kind: "exec", Cmd: &line})
	if err != nil {
		t.Fatal(err)
	}
	<-ch
	res := &pb.CommandResult{CommandId: cmd.ID.String(), AgentId: agentID.String(), Status: pb.CommandResult_SUCCEEDED, Stdout: "正确结果"}
	h.Complete(ctx, other, res)
	if got := db.Command.GetX(ctx, cmd.ID); got.Status != "sent" || got.Stdout != nil {
		t.Fatalf("跨资产回执被接受: %+v", got)
	}
	h.Complete(ctx, agentID, res)
	res.Status = pb.CommandResult_FAILED
	res.Stdout = "重复回执"
	h.Complete(ctx, agentID, res)
	got := db.Command.GetX(ctx, cmd.ID)
	if got.Status != "succeeded" || *got.Stdout != "正确结果" {
		t.Fatalf("终态被覆盖: %+v", got)
	}
}

type completingRouter struct {
	hub      *Hub
	fail     bool
	complete bool
}

func (r completingRouter) Attach(uuid.UUID, func(*pb.Command) error) func() { return func() {} }
func (r completingRouter) Online(context.Context, uuid.UUID) bool           { return true }
func (r completingRouter) Close()                                           {}
func (r completingRouter) Deliver(ctx context.Context, id uuid.UUID, c *pb.Command) error {
	if r.complete {
		r.hub.Complete(ctx, id, &pb.CommandResult{CommandId: c.Id, Status: pb.CommandResult_SUCCEEDED, Stdout: "done"})
	}
	if r.fail {
		return errors.New("投递确认超时")
	}
	return nil
}

func TestDeliveryCannotOverwriteEarlyResult(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			ctx, db := testdb.New(t)
			id := uuid.New()
			a := db.Asset.Create().SetHostname("remote").SetAgentID(id).SaveX(ctx)
			h := NewHub(db, true)
			h.Router = completingRouter{hub: h, fail: fail, complete: true}
			line := "whoami"
			cmd, err := h.Issue(ctx, Request{AssetID: a.ID, Kind: "exec", Cmd: &line})
			if err != nil {
				t.Fatal(err)
			}
			if cmd.Status != "succeeded" || cmd.Stdout == nil || *cmd.Stdout != "done" {
				t.Fatalf("快速回执被覆盖: %+v", cmd)
			}
		})
	}
}
func TestExecUnknownDeliveryAndNoReplay(t *testing.T) {
	ctx, db := testdb.New(t)
	id := uuid.New()
	a := db.Asset.Create().SetHostname("remote").SetAgentID(id).SaveX(ctx)
	h := NewHub(db, true)
	h.Router = completingRouter{hub: h, fail: true}
	line := "whoami"
	cmd, err := h.Issue(ctx, Request{AssetID: a.ID, Kind: "exec", Cmd: &line})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Status != "unknown" || cmd.CompletedAt != nil {
		t.Fatalf("不能把未知投递当作失败: %+v", cmd)
	}
	ch := h.Attach(id)
	exec, err := h.Issue(ctx, Request{AssetID: a.ID, Kind: "exec", Cmd: &line})
	if err != nil {
		t.Fatal(err)
	}
	<-ch
	kill, err := h.Issue(ctx, Request{AssetID: a.ID, Kind: "kill_process"})
	if err != nil {
		t.Fatal(err)
	}
	<-ch
	pending := h.PendingFor(ctx, id)
	if len(pending) != 1 || pending[0].ID != kill.ID {
		t.Fatalf("重连不得重放 EXEC %s: %+v", exec.ID, pending)
	}
	h.Complete(ctx, id, &pb.CommandResult{CommandId: cmd.ID.String(), Status: pb.CommandResult_SUCCEEDED})
	if got := db.Command.GetX(ctx, cmd.ID); got.Status != "succeeded" {
		t.Fatal("未知投递应接受迟到的合法回执")
	}
}
