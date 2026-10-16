// Package response 响应指令的下发与审计。
//
// 这是系统里唯一能对被监控主机造成实际影响的部分，三道闸门都在这里：
//   - 全局开关 RESPONSE_ENABLED，默认关闭
//   - 指令默认 dry_run，要真执行必须显式声明
//   - 每条指令连同下发者与执行结果落库，可追溯
package response

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	entcommand "openxdr/server/ent/command"
	"openxdr/server/pb"
)

// 单个 agent 的指令缓冲。满了说明 agent 卡住，此时拒绝新指令而不是无限堆积
const pendingPerAgent = 32

// ErrDeliveryUnknown 表示已尝试投递，调用方不能将其当作未执行并重试。
var ErrDeliveryUnknown = errors.New("指令投递结果未知")

type Hub struct {
	DB      *ent.Client
	Enabled bool
	Router  Router

	mu          sync.RWMutex
	conns       map[uuid.UUID]chan *pb.Command // agent_id -> 指令通道
	routeDetach map[uuid.UUID]func()
}

func NewHub(db *ent.Client, enabled bool) *Hub {
	if !enabled {
		slog.Warn("响应能力未启用：RESPONSE_ENABLED 为 false，指令一律拒绝下发")
	}
	return &Hub{DB: db, Enabled: enabled, conns: map[uuid.UUID]chan *pb.Command{}, routeDetach: map[uuid.UUID]func(){}}
}

// Online 报告某个 agent 当前是否挂着指令通道。
func (h *Hub) Online(agentID uuid.UUID) bool {
	h.mu.RLock()
	_, ok := h.conns[agentID]
	h.mu.RUnlock()
	if ok || h.Router == nil {
		return ok
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	return h.Router.Online(ctx, agentID)
}

// Attach 认领一个 agent 的指令通道。
func (h *Hub) Attach(agentID uuid.UUID) chan *pb.Command {
	ch := make(chan *pb.Command, pendingPerAgent)
	h.mu.Lock()
	// 同一 agent 重连时挤掉旧连接，避免指令发给已经断开的那条
	if old, ok := h.conns[agentID]; ok {
		close(old)
	}
	if detach := h.routeDetach[agentID]; detach != nil {
		detach()
	}
	h.conns[agentID] = ch
	if h.Router != nil {
		h.routeDetach[agentID] = h.Router.Attach(agentID, func(cmd *pb.Command) error {
			_, err := h.enqueue(agentID, ch, cmd)
			return err
		})
	}
	h.mu.Unlock()
	return ch
}

// Detach 连接结束时摘除通道，只摘自己那条。
func (h *Hub) Detach(agentID uuid.UUID, ch chan *pb.Command) {
	h.mu.Lock()
	if cur, ok := h.conns[agentID]; ok && cur == ch {
		delete(h.conns, agentID)
		if detach := h.routeDetach[agentID]; detach != nil {
			detach()
			delete(h.routeDetach, agentID)
		}
	}
	h.mu.Unlock()
}

// Issue 下发一条指令。agent 不在线时直接失败——指令攒着等主机上线才执行，
// 到时候的处置意图很可能已经过期，比不执行更危险。
func (h *Hub) Issue(ctx context.Context, req Request) (*ent.Command, error) {
	if !h.Enabled {
		return nil, fmt.Errorf("响应能力未启用")
	}
	a, err := h.DB.Asset.Get(ctx, req.AssetID)
	if err != nil {
		return nil, fmt.Errorf("资产不存在: %w", err)
	}
	if a.AgentID == nil {
		return nil, fmt.Errorf("该资产没有 agent，无法下发指令")
	}

	create := h.DB.Command.Create().
		SetKind(req.Kind).
		SetDryRun(req.DryRun).
		SetAssetID(a.ID).
		SetIssuedBy(req.IssuedBy).
		SetNillableIncidentID(req.IncidentID).
		SetNillableProcessGUID(req.ProcessGUID).
		SetNillableCmd(req.Cmd).
		SetTimeoutMs(req.TimeoutMS)
	cmd, err := create.Save(ctx)
	if err != nil {
		return nil, err
	}

	online, err := h.enqueue(*a.AgentID, nil, req.toProto(cmd.ID))
	if online {
		if err != nil {
			return h.finish(ctx, cmd.ID, "failed", err.Error())
		}
		return h.mark(ctx, cmd.ID, "sent")
	}
	if h.Router == nil {
		return h.finish(ctx, cmd.ID, "failed", "agent 未连接指令通道")
	}
	if err := h.Router.Deliver(ctx, *a.AgentID, req.toProto(cmd.ID)); err != nil {
		// 投递响应丢失不能证明远端没有执行，EXEC 不允许自动重放。
		status := "failed"
		if req.Kind == "exec" {
			status = "unknown"
		}
		return h.finish(ctx, cmd.ID, status, err.Error())
	}
	return h.mark(ctx, cmd.ID, "sent")
}

// enqueue 与重连关闭通道共用锁；旧 Router 回调不能向新连接投递。
func (h *Hub) enqueue(agentID uuid.UUID, expected chan *pb.Command, cmd *pb.Command) (bool, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	ch, ok := h.conns[agentID]
	if !ok || (expected != nil && ch != expected) {
		return false, fmt.Errorf("agent 指令连接已失效")
	}
	select {
	case ch <- cmd:
		return true, nil
	default:
		return true, fmt.Errorf("agent 指令队列已满")
	}
}

type Request struct {
	AssetID     uuid.UUID
	Kind        string
	DryRun      bool
	IncidentID  *uuid.UUID
	ProcessGUID *uuid.UUID
	PID         uint32
	IssuedBy    string
	// 隔离时必须放行的地址，务必包含 server 自身，否则解除隔离的指令再也送不进去
	AllowEndpoints []string
	// exec 用：命令行与超时（0 交给 agent 默认值）
	Cmd       *string
	TimeoutMS uint32
}

func (r Request) toProto(id uuid.UUID) *pb.Command {
	cmd := &pb.Command{
		Id:             id.String(),
		Kind:           kindToProto(r.Kind),
		DryRun:         r.DryRun,
		Pid:            r.PID,
		AllowEndpoints: r.AllowEndpoints,
		TimeoutMs:      r.TimeoutMS,
	}
	if r.Cmd != nil {
		cmd.Cmd = *r.Cmd
	}
	if r.ProcessGUID != nil {
		cmd.ProcessGuid = r.ProcessGUID.String()
	}
	return cmd
}

// Kinds 支持的动作，同时用于 API 参数校验。
var Kinds = map[string]pb.CommandKind{
	"kill_process":   pb.CommandKind_KILL_PROCESS,
	"isolate_host":   pb.CommandKind_ISOLATE_HOST,
	"unisolate_host": pb.CommandKind_UNISOLATE_HOST,
	"exec":           pb.CommandKind_EXEC,
}

func kindToProto(kind string) pb.CommandKind {
	return Kinds[kind]
}

// resultStatus 把上报的 proto 状态归一成库里的取值；未知状态一律按 failed 处理。
func resultStatus(st pb.CommandResult_Status) string {
	if s, ok := map[pb.CommandResult_Status]string{
		pb.CommandResult_SUCCEEDED:   "succeeded",
		pb.CommandResult_FAILED:      "failed",
		pb.CommandResult_UNSUPPORTED: "unsupported",
	}[st]; ok {
		return s
	}
	return "failed"
}

func (h *Hub) mark(ctx context.Context, id uuid.UUID, status string) (*ent.Command, error) {
	// 快速回执可能先于投递确认到达，不能把终态改回 sent。
	if _, err := h.DB.Command.Update().Where(entcommand.IDEQ(id), entcommand.StatusEQ("pending")).SetStatus(status).Save(ctx); err != nil {
		return nil, fmt.Errorf("%w：命令 %s 可能已下发，状态回写失败，禁止自动重试: %v", ErrDeliveryUnknown, id, err)
	}
	cmd, err := h.DB.Command.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%w：命令 %s 已投递，读取状态失败，禁止自动重试: %v", ErrDeliveryUnknown, id, err)
	}
	return cmd, nil
}

func (h *Hub) finish(ctx context.Context, id uuid.UUID, status, detail string) (*ent.Command, error) {
	update := h.DB.Command.Update().Where(entcommand.IDEQ(id), entcommand.StatusEQ("pending")).SetStatus(status).SetDetail(detail)
	if status != "unknown" {
		update.SetCompletedAt(time.Now())
	}
	if _, err := update.Save(ctx); err != nil {
		return nil, err
	}
	return h.DB.Command.Get(ctx, id)
}

func (h *Hub) finishUpdate(id uuid.UUID, status, detail string) *ent.CommandUpdateOne {
	return h.DB.Command.UpdateOneID(id).
		SetStatus(status).
		SetDetail(detail).
		SetCompletedAt(time.Now())
}

// ToProto 把库里的指令还原成下发消息，用于断线重连后补发。
func (h *Hub) ToProto(cmd *ent.Command) *pb.Command {
	out := &pb.Command{
		Id:        cmd.ID.String(),
		Kind:      kindToProto(cmd.Kind),
		DryRun:    cmd.DryRun,
		TimeoutMs: cmd.TimeoutMs,
	}
	if cmd.Cmd != nil {
		out.Cmd = *cmd.Cmd
	}
	if cmd.ProcessGUID != nil {
		out.ProcessGuid = cmd.ProcessGUID.String()
	}
	return out
}

// Complete 回写执行结果。agent 上报的 command_id 必须能对上库里的记录，
// 对不上就丢弃——不接受来路不明的执行结果污染审计。
func (h *Hub) Complete(ctx context.Context, agentID uuid.UUID, res *pb.CommandResult) {
	if res.CommandId == "" {
		return // 认领连接的首条消息
	}
	id, err := uuid.Parse(res.CommandId)
	if err != nil {
		return
	}
	// agentID 来自已认证的流，不信任回执里自报的 AgentId。
	scope := entcommand.HasAssetWith(asset.AgentIDEQ(agentID))
	cmd, err := h.DB.Command.Query().Where(entcommand.IDEQ(id), scope).Only(ctx)
	if err != nil {
		slog.Warn("拒绝非所属资产的指令回执", "agent", agentID, "command", id)
		return
	}
	status := resultStatus(res.Status)
	upd := h.finishUpdate(id, status, res.Detail).Where(scope, entcommand.StatusIn("pending", "sent", "unknown"))
	if cmd.Kind == "exec" {
		upd.SetExitCode(res.ExitCode).SetStdout(res.Stdout).SetStderr(res.Stderr).SetTruncated(res.Truncated)
	}
	if _, err := upd.Save(ctx); err != nil {
		slog.Warn("回写指令结果失败", "command", id, "err", err)
	} else {
		slog.Info("指令执行完毕", "command", id, "status", status, "detail", res.Detail)
	}
}

// PendingFor 仅补发原有响应动作；EXEC 可能已经执行，重连时不得重复下发。
func (h *Hub) PendingFor(ctx context.Context, agentID uuid.UUID) []*ent.Command {
	a, err := h.DB.Asset.Query().Where(asset.AgentIDEQ(agentID)).First(ctx)
	if err != nil {
		return nil
	}
	cmds, err := h.DB.Command.Query().
		Where(entcommand.AssetIDEQ(a.ID), entcommand.StatusEQ("sent"), entcommand.KindNEQ("exec")).
		Order(ent.Asc(entcommand.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil
	}
	return cmds
}
