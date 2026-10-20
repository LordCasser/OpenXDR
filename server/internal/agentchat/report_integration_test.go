//go:build integration

package agentchat

import (
	"encoding/json"
	"strings"
	"testing"

	reportent "openxdr/server/ent/report"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/testdb"
)

// 报告统一格式：不合格的带骨架退回，合格的连同一句话结论入库，正文里模型自写的一级标题去掉
func TestReportFormat(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator("a").SetModel("m").SetStatus("running").SaveX(ctx)
	s := &Service{DB: db}
	report := func(args string) (string, error) {
		return s.tool(ctx, session, commandgate.Request{}, "report", json.RawMessage(args))
	}
	if _, err := report(`{"title":"巡检","markdown":"## 结论\n正常\n## 需要人处理\n无\n## 未验证\n无"}`); err == nil || !strings.Contains(err.Error(), "summary") {
		t.Fatalf("缺一句话结论应拒绝：%v", err)
	}
	if _, err := report(`{"title":"巡检","summary":"正常","markdown":"# 巡检\n## 结论\n正常"}`); err == nil || !strings.Contains(err.Error(), "## 需要人处理") {
		t.Fatalf("缺节应带骨架拒绝：%v", err)
	}
	if n := db.Report.Query().CountX(ctx); n != 0 {
		t.Fatalf("不合格的不应入库：%d", n)
	}
	if _, err := report(`{"title":" pve1 巡检 ","summary":"pve1 正常","markdown":"# 自写标题\n## 结论\n正常\n## 需要人处理\n无\n## 未验证\n无","level":"ok"}`); err != nil {
		t.Fatal(err)
	}
	r := db.Report.Query().OnlyX(ctx)
	if r.Title != "pve1 巡检" || r.Summary != "pve1 正常" || r.Level != "ok" || strings.Contains(r.Markdown, "自写标题") {
		t.Errorf("入库内容不符：%+v", r)
	}

	// 定时任务的报告标题固定用任务名，模型写的标题不管多长都不影响
	task := db.AgentSession.Create().SetKind("task").SetGroupID(group.ID).SetInitiator(commandgate.SystemActor).SetModel("m").SetTitle("每日主机巡检").SaveX(ctx)
	if _, err := s.tool(ctx, task, commandgate.Request{System: true}, "report", json.RawMessage(
		`{"title":"`+strings.Repeat("长", 80)+`","summary":"pve2 RAID 电池待换","markdown":"## 结论\n见下\n## 需要人处理\n换电池\n## 未验证\n无"}`)); err != nil {
		t.Fatal(err)
	}
	if got := db.Report.Query().Where(reportent.SessionIDEQ(task.ID)).OnlyX(ctx); got.Title != "每日主机巡检" || got.Summary != "pve2 RAID 电池待换" {
		t.Errorf("任务报告标题应为任务名：%+v", got)
	}
}
