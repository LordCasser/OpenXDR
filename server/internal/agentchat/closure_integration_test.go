//go:build integration

package agentchat

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/testdb"
)

// 结案建议只能给告警全在本组资产上的、未结案的事件；只写建议，不改状态；再提覆盖
func TestProposeClose(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	other := db.Group.Create().SetName("o").SaveX(ctx)
	host := db.Asset.Create().SetHostname("pve1").SetGroupID(group.ID).SaveX(ctx)
	stranger := db.Asset.Create().SetHostname("x").SetGroupID(other.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator("a").SetModel("m").SetStatus("running").SaveX(ctx)
	mine := db.Incident.Create().SetGraph(json.RawMessage(`{}`)).SetStatus("triaged").SaveX(ctx)
	db.Alert.Create().SetTs(time.Now()).SetRuleID("r").SetSeverity(3).SetAssetID(host.ID).SetIncidentID(mine.ID).SaveX(ctx)
	mixed := db.Incident.Create().SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	db.Alert.Create().SetTs(time.Now()).SetRuleID("r").SetSeverity(3).SetAssetID(host.ID).SetIncidentID(mixed.ID).SaveX(ctx)
	db.Alert.Create().SetTs(time.Now()).SetRuleID("r").SetSeverity(3).SetAssetID(stranger.ID).SetIncidentID(mixed.ID).SaveX(ctx)
	rep := db.Report.Create().SetSessionID(session.ID).SetGroupID(group.ID).SetTitle("t").SetMarkdown("m").SaveX(ctx)
	s := &Service{DB: db}
	propose := func(id, status, extra string) (string, error) {
		return s.tool(ctx, session, commandgate.Request{}, "propose_close", json.RawMessage(
			`{"incident":"`+id+`","status":"`+status+`","note":"VM100 vpn-proxy 每天 10:58 解析订阅域名，良性"`+extra+`}`))
	}
	if _, err := propose(mixed.ID.String(), "false_positive", ""); err == nil {
		t.Fatal("跨组的事件不能提")
	}
	if out, err := propose(mine.ID.String(), "false_positive", `,"report":"`+rep.ID.String()+`"`); err != nil || !strings.Contains(out, "proposed") {
		t.Fatalf("应提交建议: %s %v", out, err)
	}
	got := db.Incident.GetX(ctx, mine.ID)
	if got.Status != "triaged" || got.ClosureProposal == nil || got.ClosureProposal.Status != "false_positive" ||
		got.ClosureProposal.ReportID == nil || *got.ClosureProposal.ReportID != rep.ID || got.ClosureProposal.SessionID != session.ID {
		t.Fatalf("只写建议、不改状态: %+v %+v", got.Status, got.ClosureProposal)
	}
	if _, err := propose(mine.ID.String(), "closed", ""); err != nil || db.Incident.GetX(ctx, mine.ID).ClosureProposal.Status != "closed" {
		t.Fatalf("再提应覆盖: %v", err)
	}
	db.Incident.UpdateOne(got).SetStatus("closed").ExecX(ctx)
	if out, _ := propose(mine.ID.String(), "closed", ""); !strings.Contains(out, "already_closed") {
		t.Fatalf("已结案的不再提: %s", out)
	}
}
