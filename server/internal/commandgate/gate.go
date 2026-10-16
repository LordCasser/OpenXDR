// Package commandgate 统一人工与 AI 的 exec 判权、名单和审批。
package commandgate

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/approval"
	"openxdr/server/ent/commandpolicy"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/response"
)

type Gate struct {
	DB              *ent.Client
	Hub             *response.Hub
	ApprovalTimeout time.Duration
}
type Request struct {
	UserID    uuid.UUID
	GroupID   uuid.UUID
	SessionID *uuid.UUID
	Origin    string
	Command   response.Request
}

// Match 使用完整字符串正则，避免无意放行前后拼接的命令。
func Match(pattern, cmd string) (bool, error) {
	if len(pattern) == 0 || len(pattern) > 4096 {
		return false, errors.New("pattern 长度须为 1–4096")
	}
	re, err := regexp.Compile(`\A(?:` + pattern + `)\z`)
	if err != nil {
		return false, err
	}
	return re.MatchString(cmd), nil
}

func (g *Gate) authorize(ctx context.Context, req Request) (*ent.User, error) {
	u, err := g.DB.User.Get(ctx, req.UserID)
	if err != nil {
		return nil, errors.New("发起人不存在")
	}
	if !auth.Allowed(auth.GroupRole(ctx, g.DB, u, req.GroupID), "analyst") {
		return nil, errors.New("无组内执行权限")
	}
	a, err := g.DB.Asset.Get(ctx, req.Command.AssetID)
	if err != nil || a.GroupID == nil || *a.GroupID != req.GroupID {
		return nil, errors.New("资产不属于当前组")
	}
	if req.SessionID != nil {
		s, err := g.DB.AgentSession.Get(ctx, *req.SessionID)
		if err != nil || s.GroupID != req.GroupID || s.Initiator != u.Username {
			return nil, errors.New("会话身份不匹配")
		}
	}
	return u, nil
}

func (g *Gate) needsApproval(ctx context.Context, req Request) (bool, error) {
	policies, err := g.DB.CommandPolicy.Query().Where(commandpolicy.GroupIDEQ(req.GroupID), commandpolicy.OriginEQ(commandpolicy.Origin(req.Origin))).All(ctx)
	if err != nil {
		return false, err
	}
	matched := false
	for _, policy := range policies {
		expected := commandpolicy.ModeAllow
		if req.Origin == "human" {
			expected = commandpolicy.ModeDeny
		}
		if policy.Mode != expected {
			return false, errors.New("名单模式与来源不一致")
		}
		ok, err := Match(policy.Pattern, *req.Command.Cmd)
		if err != nil {
			return false, fmt.Errorf("名单无效: %w", err)
		}
		matched = matched || ok
	}
	if req.Origin == "ai" {
		return !matched, nil
	}
	return matched, nil
}

// Issue 的 origin 由平台入口固定，不能从客户端或模型参数读取。
func (g *Gate) Issue(ctx context.Context, req Request) (out *ent.Command, retErr error) {
	if req.Origin != "ai" && req.Origin != "human" {
		return nil, errors.New("无效的命令来源")
	}
	if req.Command.Kind != "exec" || req.Command.Cmd == nil || strings.TrimSpace(*req.Command.Cmd) == "" || len(*req.Command.Cmd) > 32768 {
		return nil, errors.New("exec 命令长度须为 1–32768")
	}
	if req.Command.TimeoutMS > 300000 {
		return nil, errors.New("命令超时不可超过 300 秒")
	}
	// 请求先持久化审计，包括随后因授权、名单或超时被拒绝的请求。
	detail := fmt.Sprintf("origin=%s group=%s dry_run=%t cmd=%s", req.Origin, req.GroupID, req.Command.DryRun, *req.Command.Cmd)
	if err := g.log(ctx, req.UserID.String(), "exec_requested", req.Command.AssetID.String(), detail); err != nil {
		return nil, err
	}
	defer func() {
		logCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		status := "exec_issued"
		result := ""
		if retErr != nil {
			status = "exec_denied"
			result = retErr.Error()
		}
		if out != nil {
			result = out.ID.String() + " " + out.Status
		}
		if errors.Is(retErr, response.ErrDeliveryUnknown) || (out != nil && out.Status == "unknown") {
			status = "exec_unknown"
		}
		if err := g.log(logCtx, req.UserID.String(), status, req.Command.AssetID.String(), result); err != nil && retErr == nil {
			retErr = fmt.Errorf("命令可能已下发，审计回写失败，禁止自动重试: %w", err)
		}
	}()
	u, err := g.authorize(ctx, req)
	if err != nil {
		return nil, err
	}
	if g.Hub == nil || !g.Hub.Enabled {
		return nil, errors.New("响应能力未启用")
	}
	required, err := g.needsApproval(ctx, req)
	if err != nil {
		return nil, err
	}
	if required {
		if err := g.await(ctx, req, u.Username); err != nil {
			return nil, err
		}
	}
	// 等待期间主机归组或成员权限可能改变，审批不能越过此检查。
	u, err = g.authorize(ctx, req)
	if err != nil {
		return nil, err
	}
	req.Command.IssuedBy = u.Username
	return g.Hub.Issue(ctx, req.Command)
}

func (g *Gate) log(ctx context.Context, actor, action, target, detail string) error {
	return g.DB.AuditLog.Create().SetUsername(actor).SetAction(action).SetTarget(target).SetDetail(detail).SetRemoteAddr("server").Exec(ctx)
}

func (g *Gate) await(ctx context.Context, req Request, username string) error {
	ttl := g.ApprovalTimeout
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	expires := time.Now().Add(ttl)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	a, err := g.DB.Approval.Create().SetGroupID(req.GroupID).SetNillableSessionID(req.SessionID).
		SetAssetID(req.Command.AssetID).SetRequestedBy(username).SetOrigin(approval.Origin(req.Origin)).
		SetCmd(*req.Command.Cmd).SetTimeoutMs(req.Command.TimeoutMS).SetDryRun(req.Command.DryRun).SetExpiresAt(expires).Save(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		status := approval.StatusCancelled
		if !time.Now().Before(expires) {
			status = approval.StatusExpired
		}
		_, _ = g.DB.Approval.Update().Where(approval.IDEQ(a.ID), approval.StatusIn(approval.StatusPending, approval.StatusApproved)).SetStatus(status).Save(cleanup)
	}()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(time.Until(expires))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return errors.New("审批超时，命令未执行")
		case <-ticker.C:
			current, err := g.DB.Approval.Get(ctx, a.ID)
			if err != nil {
				return err
			}
			switch current.Status {
			case approval.StatusApproved:
				// 原子消费，批准不能被重复使用；过期的批准同样不能执行。
				n, err := g.DB.Approval.Update().Where(approval.IDEQ(a.ID), approval.StatusEQ(approval.StatusApproved), approval.ExpiresAtGT(time.Now())).SetStatus(approval.StatusConsumed).Save(ctx)
				if err != nil {
					return err
				}
				if n != 1 {
					return errors.New("审批已过期或已消费")
				}
				return nil
			case approval.StatusPending:
			default:
				return errors.New("审批未通过，命令未执行")
			}
		}
	}
}

// Decide 在数据库中原子决定并写审计；多个节点竞争只能成功一次。
func (g *Gate) Decide(ctx context.Context, id uuid.UUID, u *ent.User, approved bool) error {
	a, err := g.DB.Approval.Get(ctx, id)
	if err != nil {
		return err
	}
	if u == nil || !auth.Allowed(auth.GroupRole(ctx, g.DB, u, a.GroupID), "admin") {
		return errors.New("只有组内 admin 可以审批")
	}
	tx, err := g.DB.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	status := approval.StatusRejected
	if approved {
		status = approval.StatusApproved
	}
	n, err := tx.Approval.Update().Where(approval.IDEQ(id), approval.StatusEQ(approval.StatusPending), approval.ExpiresAtGT(time.Now())).SetStatus(status).SetDecidedBy(u.Username).SetDecidedAt(time.Now()).Save(ctx)
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("审批已结束或已过期")
	}
	if err := tx.AuditLog.Create().SetUsername(u.Username).SetAction("approval_decided").SetTarget(id.String()).SetDetail(string(status)).SetRemoteAddr("server").Exec(ctx); err != nil {
		return err
	}
	return tx.Commit()
}
