package grpcsvc

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"openxdr/server/internal/response"
	"openxdr/server/pb"
)

// ReportCommandResult 只有数据库完成回执写入或已有合法终态后才确认指令 ID。
// ACK 不表示主机动作效果成立，也不会再次投递指令；已有终态保持首次结果。
func (s *Server) ReportCommandResult(ctx context.Context, result *pb.CommandResult) (*pb.CommandResultAck, error) {
	if result == nil {
		return nil, status.Error(codes.InvalidArgument, "缺少指令回执")
	}
	agentID, err := uuid.Parse(result.AgentId)
	if err != nil || agentID == uuid.Nil {
		return nil, status.Error(codes.InvalidArgument, "agent_id 无效")
	}
	commandID, err := uuid.Parse(result.CommandId)
	if err != nil || commandID == uuid.Nil {
		return nil, status.Error(codes.InvalidArgument, "command_id 无效")
	}
	// UNSPECIFIED 表示执行被 agent 停机或重启打断、结果未知，记为 unknown 交人核实
	if _, ok := pb.CommandResult_Status_name[int32(result.Status)]; !ok {
		return nil, status.Error(codes.InvalidArgument, "回执状态无效")
	}
	if err := s.verifyAgentID(ctx, agentID); err != nil {
		return nil, err
	}
	if s.Hub == nil {
		return nil, status.Error(codes.Unavailable, "回执存储未就绪")
	}
	if err := s.Hub.Complete(ctx, agentID, result); errors.Is(err, response.ErrReceiptRejected) {
		return nil, status.Error(codes.NotFound, err.Error())
	} else if err != nil {
		slog.Warn("独立指令回执未确认", "agent", agentID, "command", commandID, "err", err)
		return nil, status.Error(codes.Unavailable, "回执尚未确认持久化，保留结果等待重传；不要重执行动作")
	}
	return &pb.CommandResultAck{CommandId: commandID.String()}, nil
}
