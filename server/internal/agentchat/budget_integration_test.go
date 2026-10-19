//go:build integration

package agentchat

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"openxdr/server/internal/testdb"
)

// 额度按组算近 24 小时助手消息的输入加输出；别的组、更早的、非助手消息不算
func TestGroupBudget(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	other := db.Group.Create().SetName("o").SaveX(ctx)
	mine := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator("a").SetModel("m").SaveX(ctx)
	theirs := db.AgentSession.Create().SetKind("chat").SetGroupID(other.ID).SetInitiator("a").SetModel("m").SaveX(ctx)
	usage := json.RawMessage(`{"role":"assistant","usage":{"input":600,"output":100,"cacheRead":5000}}`)
	seq := 0
	add := func(session, role string, at time.Time) {
		seq++
		id := mine.ID
		if session == "theirs" {
			id = theirs.ID
		}
		db.SessionMessage.Create().SetSessionID(id).SetSeq(seq).SetRole(role).SetContent(usage).SetCreatedAt(at).ExecX(ctx)
	}
	now := time.Now()
	add("mine", "assistant", now)
	add("mine", "assistant", now.Add(-time.Hour))
	add("mine", "assistant", now.Add(-25*time.Hour))
	add("mine", "toolResult", now)
	add("theirs", "assistant", now)

	s := &Service{DB: db}
	used, err := s.groupTokens(ctx, group.ID)
	if err != nil || used != 1400 {
		t.Fatalf("本组用量应为 1400，实际 %d err=%v", used, err)
	}
	if err := s.checkBudget(ctx, group.ID); err != nil {
		t.Fatalf("不设上限时不该拦：%v", err)
	}
	s.GroupDailyTokens = 1400
	if err := s.checkBudget(ctx, group.ID); !errors.Is(err, errOverBudget) {
		t.Fatalf("到上限应拦下，实际 %v", err)
	}
	s.GroupDailyTokens = 1401
	if err := s.checkBudget(ctx, group.ID); err != nil {
		t.Fatalf("没到上限不该拦：%v", err)
	}
	if used, _ := s.groupTokens(ctx, other.ID); used != 700 {
		t.Fatalf("别的组用量应为 700，实际 %d", used)
	}
}
