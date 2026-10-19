package grpcsvc

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	if result.Status != pb.CommandResult_SUCCEEDED && result.Status != pb.CommandResult_FAILED && result.Status != pb.CommandResult_UNSUPPORTED {
		return nil, status.Error(codes.InvalidArgument, "回执必须包含明确动作结果")
	}
	if err := s.verifyAgentID(ctx, agentID); err != nil {
		return nil, err
	}
	if s.Hub == nil {
		return nil, status.Error(codes.Unavailable, "回执存储未就绪")
	}
	if err := s.Hub.Complete(ctx, agentID, result); err != nil {
		slog.Warn("独立指令回执未确认", "agent", agentID, "command", commandID, "err", err)
		return nil, status.Error(codes.Unavailable, "回执尚未确认持久化，保留结果等待重传；不要重执行动作")
	}
	return &pb.CommandResultAck{CommandId: commandID.String()}, nil
}
