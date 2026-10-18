//go:build integration

package agentchat

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/memories"
	"openxdr/server/internal/testdb"
)

// remember 写本组记忆、去重、校验主机归属；forget 只能删 AI 写的；记忆随上下文交给下一轮会话，人工的在前
func TestRememberAndForget(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	other := db.Group.Create().SetName("other").SaveX(ctx)
	host := db.Asset.Create().SetHostname("pve1").SetGroupID(group.ID).SaveX(ctx)
	stranger := db.Asset.Create().SetHostname("x").SetGroupID(other.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator("a").SetModel("m").SetStatus("running").SaveX(ctx)
	s := &Service{DB: db}
	call := func(name, args string) (string, error) {
		return s.tool(ctx, session, commandgate.Request{}, name, json.RawMessage(args))
	}

	out, err := call("remember", `{"host":"`+host.ID.String()+`","content":"  每天 04:30 跑端口巡检脚本  "}`)
	if err != nil || !strings.Contains(out, "remembered") {
		t.Fatalf("记忆写入: %s %v", out, err)
	}
	if out, _ := call("remember", `{"content":"每天 04:30 跑端口巡检脚本"}`); !strings.Contains(out, "exists") {
		t.Fatalf("重复内容应提示已有: %s", out)
	}
	if _, err := call("remember", `{"host":"`+stranger.ID.String()+`","content":"别组主机"}`); err == nil {
		t.Fatal("别组主机应拒绝")
	}
	if _, err := call("remember", `{"content":"`+strings.Repeat("长", 501)+`"}`); err == nil {
		t.Fatal("超长应拒绝")
	}
	human := db.Memory.Create().SetGroupID(group.ID).SetContent("10.1.1.100 是网关容器").SetSource("human").SetAuthor("admin").SaveX(ctx)
	if _, err := call("forget", `{"id":"`+human.ID.String()+`"}`); err == nil {
		t.Fatal("人工记忆不能被 AI 删除")
	}

	items, err := memories.Of(ctx, db, []uuid.UUID{group.ID}, map[uuid.UUID]string{host.ID: "pve1"})
	if err != nil || len(items) != 2 || items[0]["source"] != "human" || items[1]["host"] != "pve1" {
		t.Fatalf("记忆列表应人工在前、带主机名: %+v %v", items, err)
	}
	if out, err := call("memories", `{}`); err != nil || !strings.Contains(out, "每天 04:30 跑端口巡检脚本") || !strings.Contains(out, "10.1.1.100 是网关容器") {
		t.Fatalf("实时列表应包含刚写的记忆: %s %v", out, err)
	}
	data, _, _, err := s.contextData(ctx, session)
	if err != nil || len(data["memories"].([]map[string]any)) != 2 {
		t.Fatalf("上下文应带记忆: %v", err)
	}

	for _, m := range db.Memory.Query().AllX(ctx) {
		if m.Source != "ai" {
			continue
		}
		if m.Content != "每天 04:30 跑端口巡检脚本" || m.SessionID == nil || *m.SessionID != session.ID {
			t.Fatalf("AI 记忆应去掉首尾空白并记下会话: %+v", m)
		}
		if out, err := call("forget", `{"id":"`+m.ID.String()+`"}`); err != nil || !strings.Contains(out, "forgotten") {
			t.Fatalf("删除 AI 记忆: %s %v", out, err)
		}
	}
	if n := db.Memory.Query().CountX(ctx); n != 1 {
		t.Fatalf("应只剩人工记忆: %d", n)
	}
}
