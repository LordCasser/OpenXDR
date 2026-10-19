package grpcsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"openxdr/server/ent/asset"
	"openxdr/server/pb"
)

type capability struct {
	Path  string `json:"path"`
	State string `json:"state"`
}
type receiptHealth struct {
	Pending    uint64 `json:"pending"`
	Incomplete uint64 `json:"incomplete"`
}
type collectorHealth struct {
	Receipts        *receiptHealth        `json:"receipts,omitempty"`
	BootID          string                `json:"bootId"`
	Sequence        uint64                `json:"sequence"`
	ReportedUnixMs  int64                 `json:"reportedUnixMs"`
	QueueBytes      uint64                `json:"queueBytes"`
	QueueBatches    uint64                `json:"queueBatches"`
	QueueLimitBytes uint64                `json:"queueLimitBytes"`
	DroppedEvents   uint64                `json:"droppedEvents"`
	WriteBlocked    bool                  `json:"writeBlocked"`
	Capabilities    map[string]capability `json:"capabilities"`
}

func parseHealth(raw string, now time.Time) (collectorHealth, error) {
	var h collectorHealth
	if len(raw) > 16*1024 {
		return h, status.Error(codes.InvalidArgument, "采集状态超过大小上限")
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&h) != nil || decoder.Decode(new(any)) != io.EOF {
		return h, status.Error(codes.InvalidArgument, "采集状态格式无效")
	}
	_, err := uuid.Parse(h.BootID)
	const safeInteger = 1<<53 - 1
	if err != nil || h.Sequence == 0 || h.Sequence > safeInteger || h.QueueBytes > safeInteger || h.QueueLimitBytes > safeInteger || h.DroppedEvents > safeInteger || h.QueueBatches > 8192 || len(h.Capabilities) > 16 {
		return h, status.Error(codes.InvalidArgument, "采集状态字段越界")
	}
	if r := h.Receipts; r != nil && (r.Pending > 256 || r.Incomplete > 256 || r.Pending+r.Incomplete > 256) {
		return h, status.Error(codes.InvalidArgument, "回执缓存数量越界")
	}
	reported := time.UnixMilli(h.ReportedUnixMs)
	if reported.Before(now.Add(-5*time.Minute)) || reported.After(now.Add(5*time.Minute)) {
		return h, status.Error(codes.InvalidArgument, "状态时间与服务端相差超过 5 分钟，请校准时钟")
	}
	for name, cap := range h.Capabilities {
		switch name {
		case "process", "files", "network", "dns", "auth", "inventory", "local-accounts", "persist", "kmod", "powershell", "software":
		default:
			return h, status.Error(codes.InvalidArgument, "未知采集组件")
		}
		switch cap.State {
		case "active", "degraded", "unavailable", "disabled", "unknown":
		default:
			return h, status.Error(codes.InvalidArgument, "未知采集状态")
		}
		if len(cap.Path) > 64 {
			return h, status.Error(codes.InvalidArgument, "采集路径过长")
		}
	}
	return h, nil
}

// ReportHealth 不依赖事件总线。先验证证书归属，再原子拒绝重复或倒序状态。
func (s *Server) ReportHealth(ctx context.Context, req *pb.HealthRequest) (*pb.HealthAck, error) {
	id, err := uuid.Parse(req.AgentId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "agent_id 无效")
	}
	if err := s.verifyAgentID(ctx, id); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	h, err := parseHealth(req.HealthJson, now)
	if err != nil {
		return nil, err
	}
	snapshot := struct {
		collectorHealth
		ReceivedAt time.Time `json:"receivedAt"`
	}{h, now}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return nil, status.Error(codes.Internal, "状态编码失败")
	}
	// 同一次启动使用序号；启动变化时还要求采样时刻不倒退。
	n, err := s.DB.Asset.Update().Where(asset.AgentIDEQ(id), func(sel *sql.Selector) {
		sel.Where(sql.P(func(b *sql.Builder) {
			b.WriteString("(collector_health IS NULL OR collector_health = 'null'::jsonb OR ((collector_health->>'bootId' = ").Arg(h.BootID)
			b.WriteString(" AND (collector_health->>'sequence')::numeric < ").Arg(h.Sequence)
			b.WriteString(") OR (collector_health->>'bootId' <> ").Arg(h.BootID)
			b.WriteString(" AND (collector_health->>'reportedUnixMs')::bigint < ").Arg(h.ReportedUnixMs).WriteString(")))")
		}))
	}).SetCollectorHealth(raw).SetLastSeen(now).Save(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "采集状态保存失败")
	}
	if n == 0 {
		exists, err := s.DB.Asset.Query().Where(asset.AgentIDEQ(id)).Exist(ctx)
		if err != nil {
			return nil, status.Error(codes.Internal, "资产核对失败")
		}
		if !exists {
			return nil, status.Error(codes.NotFound, "agent 尚未注册")
		}
	}
	return &pb.HealthAck{}, nil
}
