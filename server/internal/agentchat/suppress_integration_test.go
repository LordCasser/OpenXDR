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

// AI 只能对本组主机上真实命中过的规则提议抑制；提议不生效、不重复，被拒绝过的不再接受
func TestSuppressProposal(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	other := db.Group.Create().SetName("o").SaveX(ctx)
	host := db.Asset.Create().SetHostname("pve1").SetGroupID(group.ID).SaveX(ctx)
	stranger := db.Asset.Create().SetHostname("x").SetGroupID(other.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator("a").SetModel("m").SetStatus("running").SaveX(ctx)
	db.Alert.Create().SetTs(time.Now()).SetRuleID("probe").SetSeverity(2).SetAssetID(host.ID).SaveX(ctx)
	cmd := db.Command.Create().SetKind("exec").SetAssetID(host.ID).SaveX(ctx)
	db.Alert.Create().SetTs(time.Now()).SetRuleID("own").SetSeverity(2).SetAssetID(host.ID).SetCommandID(cmd.ID).SaveX(ctx)
	s := &Service{DB: db}
	propose := func(host, rule string) (string, error) {
		return s.tool(ctx, session, commandgate.Request{}, "suppress", json.RawMessage(
			`{"host":"`+host+`","rule_id":"`+rule+`","reason":"cron 每天 04:30 跑端口巡检脚本，例行业务","days":30}`))
	}
	if _, err := propose(stranger.ID.String(), "probe"); err == nil {
		t.Fatal("别组主机应拒绝")
	}
	if _, err := propose(host.ID.String(), "never-hit"); err == nil {
		t.Fatal("没命中过的规则应拒绝")
	}
	if _, err := propose(host.ID.String(), "own"); err == nil {
		t.Fatal("只有平台指令触发过的规则不需要抑制")
	}
	out, err := propose(host.ID.String(), "probe")
	if err != nil || !strings.Contains(out, "proposed") {
		t.Fatalf("应提交提议: %s %v", out, err)
	}
	p := db.Suppression.Query().OnlyX(ctx)
	if p.Status != "proposed" || p.SessionID == nil || *p.SessionID != session.ID || p.AssetID == nil || *p.AssetID != host.ID {
		t.Fatalf("提议应待批准、记下会话与主机: %+v", p)
	}
	if out, _ := propose(host.ID.String(), "probe"); !strings.Contains(out, "pending") {
		t.Fatalf("已有待批准的不重复提: %s", out)
	}
	db.Suppression.UpdateOne(p).SetStatus("rejected").SetReviewedAt(time.Now()).ExecX(ctx)
	if out, _ := propose(host.ID.String(), "probe"); !strings.Contains(out, "rejected") {
		t.Fatalf("30 天内拒绝过的不再接受: %s", out)
	}
}
