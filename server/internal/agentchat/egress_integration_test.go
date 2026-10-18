//go:build integration

package agentchat

import (
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/assetmap"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/testdb"
)

// 外联调查结论：只认本组主机真实连过的公网地址；内网地址、没连过的地址、别组主机都拒绝；人工结论不被覆盖。
func TestEgressConclusion(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	other := db.Group.Create().SetName("o").SaveX(ctx)
	host := db.Asset.Create().SetHostname("pve2").SetIPAddrs([]string{"10.1.1.12"}).SetGroupID(group.ID).SaveX(ctx)
	stranger := db.Asset.Create().SetHostname("x").SetGroupID(other.ID).SaveX(ctx)
	now := time.Now()
	for _, dst := range []string{"208.111.34.178", "10.1.1.170"} {
		db.AssetLink.Create().SetSrcIP("10.1.1.12").SetSrcAssetID(host.ID).SetDstIP(dst).SetDstPort(443).SetProto("tcp").
			SetProcess("tailscaled").SetCount(3).SetFirstSeen(now).SetLastSeen(now).SaveX(ctx)
	}
	session := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator("kei").
		SetModel("m").SetStatus("running").SetTitle("调查").SaveX(ctx)
	s := &Service{DB: db}
	egress := func(host, ip string) (string, error) {
		return s.tool(ctx, session, commandgate.Request{}, "egress", []byte(
			`{"host":"`+host+`","ip":"`+ip+`","name":"Tailscale 中继","note":"tailscaled 连 DERP 中继，组网正常业务","risk":"low"}`))
	}

	for _, bad := range [][2]string{{stranger.ID.String(), "208.111.34.178"}, {host.ID.String(), "10.1.1.170"}, {host.ID.String(), "1.2.3.4"}} {
		if _, err := egress(bad[0], bad[1]); err == nil {
			t.Fatalf("应拒绝 %v", bad)
		}
	}
	if out, err := egress(host.ID.String(), "208.111.34.178"); err != nil || !strings.Contains(out, "recorded") {
		t.Fatalf("应写入: %s %v", out, err)
	}
	n := assetmap.EgressNotesOf(db.Asset.GetX(ctx, host.ID))["208.111.34.178"]
	if n.Name != "Tailscale 中继" || n.Source != "investigation" || n.By != session.ID.String() || n.Risk != "low" {
		t.Fatalf("结论不对: %+v", n)
	}
	// 接口给出的外联明细带上结论
	dests := assetmap.WithNotes([]assetmap.PublicDest{{IP: "208.111.34.178"}}, db.Asset.GetX(ctx, host.ID))
	if dests[0].Note == nil || dests[0].Note.Name != "Tailscale 中继" {
		t.Fatalf("明细应带结论: %+v", dests[0])
	}

	if err := assetmap.SetEgressNote(ctx, db, host.ID, "208.111.34.178", assetmap.ServiceNote{Name: "人工确认", Source: "human"}); err != nil {
		t.Fatal(err)
	}
	if out, err := egress(host.ID.String(), "208.111.34.178"); err != nil || !strings.Contains(out, "locked") {
		t.Fatalf("人工结论应挡住调查: %s %v", out, err)
	}
}
