//go:build integration

package agentchat

import (
	"encoding/json"
	"strings"
	"testing"

	"openxdr/server/internal/assetmap"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/testdb"
)

// 调查结论写回服务说明：只认本组主机上真实存在的监听；人工结论不被覆盖。
func TestIdentifyService(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	other := db.Group.Create().SetName("o").SaveX(ctx)
	listen := json.RawMessage(`[{"proto":"udp","addr":"10.1.1.2","port":5405,"process":"corosync"}]`)
	host := db.Asset.Create().SetHostname("pve1").SetGroupID(group.ID).SetListening(listen).SaveX(ctx)
	stranger := db.Asset.Create().SetHostname("x").SetGroupID(other.ID).SetListening(listen).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator("kei").
		SetModel("m").SetStatus("running").SetTitle("调查").SaveX(ctx)
	s := &Service{DB: db}
	identify := func(host, port string) (string, error) {
		return s.tool(ctx, session, commandgate.Request{}, "identify", []byte(
			`{"host":"`+host+`","port":"`+port+`","name":"Corosync 集群通信","note":"corosync 进程，PVE 集群心跳","risk":"low"}`))
	}

	if _, err := identify(stranger.ID.String(), "udp/5405"); err == nil {
		t.Fatal("别组主机不能写")
	}
	if _, err := identify(host.ID.String(), "tcp/9999"); err == nil {
		t.Fatal("主机上没有的监听不能写")
	}
	if out, err := identify(host.ID.String(), "udp/5405"); err != nil || !strings.Contains(out, "recorded") {
		t.Fatalf("应写入: %s %v", out, err)
	}
	var notes map[string]assetmap.ServiceNote
	_ = json.Unmarshal(db.Asset.GetX(ctx, host.ID).ServiceNotes, &notes)
	if n := notes["udp/5405"]; n.Source != "investigation" || n.By != session.ID.String() || n.Risk != "low" {
		t.Fatalf("来源应为 investigation 并记下会话: %+v", n)
	}

	// 人工确认后，调查与 AI 标注都不能覆盖
	if err := assetmap.SetServiceNote(ctx, db, host.ID, "udp/5405", assetmap.ServiceNote{Name: "集群心跳", Source: "human"}); err != nil {
		t.Fatal(err)
	}
	if out, err := identify(host.ID.String(), "udp/5405"); err != nil || !strings.Contains(out, "locked") {
		t.Fatalf("人工结论应挡住调查: %s %v", out, err)
	}
	if err := assetmap.SetServiceNote(ctx, db, host.ID, "udp/5405", assetmap.ServiceNote{Name: "猜的", Source: "ai"}); !assetmap.IsLowerSource(err) {
		t.Fatalf("人工结论应挡住 AI 标注: %v", err)
	}
}
