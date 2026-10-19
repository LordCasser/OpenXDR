//go:build integration

package grpcsvc

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"openxdr/server/ent"
	"openxdr/server/ent/hook"
	"openxdr/server/internal/response"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

func TestReceiptAckRequiresPersistence(t *testing.T) {
	ctx, db := testdb.New(t)
	agentID := uuid.New()
	host := db.Asset.Create().SetHostname("receipt-ack").SetAgentID(agentID).SaveX(ctx)
	cmd := db.Command.Create().SetAssetID(host.ID).SetKind("exec").SetStatus("sent").SaveX(ctx)
	s := &Server{DB: db, Hub: response.NewHub(db, true)}
	result := &pb.CommandResult{AgentId: agentID.String(), CommandId: cmd.ID.String(), Status: pb.CommandResult_SUCCEEDED, Stdout: "done"}
	fail := true
	db.Command.Use(func(next ent.Mutator) ent.Mutator {
		return hook.CommandFunc(func(ctx context.Context, m *ent.CommandMutation) (ent.Value, error) {
			if fail {
				return nil, errors.New("模拟写入失败")
			}
			return next.Mutate(ctx, m)
		})
	})
	if ack, err := s.ReportCommandResult(ctx, result); err == nil || ack != nil {
		t.Fatal("未落库就 ACK")
	}
	if db.Command.GetX(ctx, cmd.ID).Status != "sent" {
		t.Fatal("失败生成终态")
	}
	fail = false
	for range 2 {
		ack, err := s.ReportCommandResult(ctx, result)
		if err != nil || ack.CommandId != cmd.ID.String() {
			t.Fatalf("回执恢复/重传失败: %v", err)
		}
	}
	result.AgentId = uuid.NewString()
	if ack, err := s.ReportCommandResult(ctx, result); err == nil || ack != nil {
		t.Fatal("错误 agent 得到 ACK")
	}
	result.AgentId = agentID.String()
	// 被打断的执行报结果未知：已有终态时确认但不覆盖
	result.Status = pb.CommandResult_STATUS_UNSPECIFIED
	if _, err := s.ReportCommandResult(ctx, result); err != nil {
		t.Fatalf("结果未知的重复回执应当确认: %v", err)
	}
	if db.Command.GetX(ctx, cmd.ID).Status != "succeeded" {
		t.Fatal("结果未知覆盖了终态")
	}
	if db.Command.Query().CountX(ctx) != 1 {
		t.Fatal("回执重传重新创建动作")
	}

	// 没有终态的指令记为 unknown，交人核实
	open := db.Command.Create().SetAssetID(host.ID).SetKind("kill_process").SetStatus("sent").SaveX(ctx)
	result.CommandId = open.ID.String()
	if _, err := s.ReportCommandResult(ctx, result); err != nil {
		t.Fatalf("结果未知的回执未确认: %v", err)
	}
	if got := db.Command.GetX(ctx, open.ID).Status; got != "unknown" {
		t.Fatalf("结果未知应记 unknown，实际 %s", got)
	}

	// 库里没有的指令：明确拒收，agent 据此丢弃而不是无限重传
	result.CommandId = uuid.NewString()
	if _, err := s.ReportCommandResult(ctx, result); status.Code(err) != codes.NotFound {
		t.Fatalf("不存在的指令应返回 NotFound，实际 %v", err)
	}
}
