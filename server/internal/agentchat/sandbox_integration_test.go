//go:build integration

package agentchat

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/testdb"
)

// 工具令牌：只认签发的会话；能调的工具与会话内的 Pi 相同；发起人失去组内分析权限后立即失效。
func TestSandboxCall(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	host := db.Asset.Create().SetHostname("pve1").SetGroupID(group.ID).SaveX(ctx)
	u := db.User.Create().SetUsername("kei").SetPasswordHash("x").SetRole("viewer").SaveX(ctx)
	member := db.GroupMember.Create().SetGroupID(group.ID).SetUserID(u.ID).SetRole("analyst").SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator("kei").SetModel("m").SetStatus("idle").SetTitle("t").SaveX(ctx)
	s := &Service{DB: db}

	token, expires, err := s.IssueSandboxToken(ctx, session, u)
	if err != nil || len(token) != 64 || time.Until(expires) < 3*time.Hour {
		t.Fatalf("签发: %v", err)
	}
	if strings.Contains(string(db.Setting.Query().OnlyX(ctx).ID), token) {
		t.Fatal("库里只能存令牌哈希")
	}
	out, err := s.SandboxCall(ctx, token, "context", nil)
	if err != nil || !strings.Contains(out, "pve1") {
		t.Fatalf("context 应返回组内资产: %s %v", out, err)
	}
	out, err = s.SandboxCall(ctx, token, "track", json.RawMessage(`{"host":"`+host.ID.String()+`","key":"disk-full","title":"磁盘满","detail":"/ 98%","severity":"medium","status":"open"}`))
	if err != nil || !strings.Contains(out, `"new":true`) {
		t.Fatalf("track 应与会话内一致: %s %v", out, err)
	}
	if _, err := s.SandboxCall(ctx, token, "bash", nil); err == nil || IsSandboxTokenError(err) {
		t.Fatal("未知工具应拒绝")
	}
	if _, err := s.SandboxCall(ctx, "deadbeef", "context", nil); !IsSandboxTokenError(err) {
		t.Fatal("伪造令牌应判为令牌错误")
	}
	db.GroupMember.UpdateOne(member).SetRole("viewer").ExecX(ctx)
	if _, err := s.SandboxCall(ctx, token, "context", nil); err == nil {
		t.Fatal("降为 viewer 后令牌应不可用")
	}
}
