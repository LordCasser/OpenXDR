// Package audit 操作审计。谁、何时、从哪里、做了什么——
// 写入失败只记日志不阻断业务：审计是留痕，不是闸门。
package audit

import (
	"context"
	"log/slog"
	"net"
	"net/http"

	"openxdr/server/ent"
)

type actorKey struct{}

// WithActor 把操作者身份放进请求上下文，由认证中间件调用。
func WithActor(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, actorKey{}, username)
}

// Actor 取当前操作者；未认证的内部调用（如集成测试）记为 "api"。
func Actor(ctx context.Context) string {
	if v, ok := ctx.Value(actorKey{}).(string); ok {
		return v
	}
	return "api"
}

// Log 记一条审计。target/detail 可为空串，空串不落列。
func Log(ctx context.Context, db *ent.Client, r *http.Request, action, target, detail string) {
	write(ctx, db, Actor(ctx), RemoteAddr(r), action, target, detail)
}

// System 系统自动动作的审计：没有请求、没有登录用户，但同样必须留痕。
func System(ctx context.Context, db *ent.Client, action, target, detail string) {
	write(ctx, db, "system", "server", action, target, detail)
}

func write(ctx context.Context, db *ent.Client, username, remote, action, target, detail string) {
	if err := Checked(ctx, db.AuditLog.Create(), username, remote, action, target, detail); err != nil {
		slog.Error("审计写入失败", "action", action, "err", err)
	}
}

// Checked 事务内或需要感知失败的审计写入：返回错误让调用方回滚，
// 不出现“操作落库而审计丢失”。字段语义同 Log，空串不落列。
func Checked(ctx context.Context, create *ent.AuditLogCreate, username, remote, action, target, detail string) error {
	c := create.SetUsername(username).SetAction(action).SetRemoteAddr(remote)
	if target != "" {
		c.SetTarget(target)
	}
	if detail != "" {
		c.SetDetail(detail)
	}
	return c.Exec(ctx)
}

// RemoteAddr 请求的来源地址（realip 中间件已还原），与事务里自己写审计的地方共用
func RemoteAddr(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
