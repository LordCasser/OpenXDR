//go:build integration

package correlate

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/internal/ingest"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

const (
	trustedFP = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
	otherFP   = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

var trustedRules = []string{`title: Recon
id: 33333333-3333-4333-8333-333333333333
status: test
tags: [attack.discovery, attack.t1082]
logsource: {category: process_creation, product: linux}
detection:
  selection:
    CommandLine|contains: recon-marker
  condition: selection
level: critical
`, `title: Dump
id: 44444444-4444-4444-8444-444444444444
status: test
tags: [attack.credential_access, attack.t1003.008]
logsource: {category: process_creation, product: linux}
detection:
  selection:
    CommandLine|contains: dump-marker
  condition: selection
level: medium
`}

// 可信自动化来源：登记后命中的告警挂在来源上、不进 incident；高危例外照常进；
// 跨组、来源地址不符、过期都不认；撤销后恢复照常告警；命中计数累加
func TestTrustedSourceAlertsStayOutOfIncidents(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := ingest.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`TRUNCATE alert_dedup_state`); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for i, body := range trustedRules {
		if err := os.WriteFile(filepath.Join(dir, strconv.Itoa(i)+".yml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	catalog := sigma.LoadDir(dir)
	if len(catalog.Rules()) != 2 {
		t.Fatalf("测试规则应加载 2 条，实际 %d", len(catalog.Rules()))
	}
	p := &ingest.Processor{DB: db, Rules: catalog, Suppress: suppress.New(client, 0), Intel: intel.New(client, 0), DedupWindow: time.Hour}

	ops := client.Group.Create().SetName("ops").SaveX(ctx)
	other := client.Group.Create().SetName("other").SaveX(ctx)
	host := client.Asset.Create().SetHostname("pve1").SetOs("linux").SetGroupID(ops.ID).SaveX(ctx)
	foreign := client.Asset.Create().SetHostname("web1").SetOs("linux").SetGroupID(other.ID).SaveX(ctx)
	now := time.Now()
	termix := client.TrustedSource.Create().SetGroupID(ops.ID).SetName("Termix").SetCreatedBy("lead").
		SetKeyFingerprint(trustedFP).SetSourceCidr("10.1.1.35/32").SetExpiresAt(now.Add(30 * 24 * time.Hour)).SaveX(ctx)
	client.TrustedSource.Create().SetGroupID(ops.ID).SetName("过期的").SetCreatedBy("lead").
		SetKeyFingerprint(otherFP).SetExpiresAt(now.Add(-time.Hour)).SaveX(ctx)

	seq := 0
	// emit 投递一条进程事件，返回它新建的告警（并进已有告警时返回 nil）
	emit := func(asset *ent.Asset, cmd, fp, ip string) *ent.Alert {
		t.Helper()
		seq++
		raw := map[string]any{"process": map[string]any{"cmd_line": cmd}}
		if fp != "" {
			raw["login_session"] = map[string]any{"uid": "7", "user": "root", "src_ip": ip, "key_fp": fp, "auth_method": "publickey"}
		}
		body, _ := json.Marshal(raw)
		id := ingest.StableID(t.Name(), strconv.Itoa(seq))
		e := ingest.Envelope{Version: ingest.EnvelopeVersion, ID: id, PartitionKey: asset.ID.String(), AssetID: &asset.ID,
			Timestamp: now.Add(time.Duration(seq) * time.Second), ClassUID: 1007, Source: "agent", AssetOS: "linux", Raw: body}
		if err := p.Process(ctx, e); err != nil {
			t.Fatal(err)
		}
		a, err := client.Alert.Query().Where(alert.EventIDEQ(id)).Only(ctx)
		if ent.IsNotFound(err) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	trusted := emit(host, "recon-marker", trustedFP, "10.1.1.35")
	watched := emit(host, "dump-marker", trustedFP, "10.1.1.35")
	crossGroup := emit(foreign, "recon-marker", trustedFP, "10.1.1.35")
	plain := emit(host, "recon-marker", "", "")
	if trusted == nil || watched == nil || crossGroup == nil || plain == nil {
		t.Fatal("每条都应新建告警：可信来源的告警单独去重，不能吞掉之后的真实命中")
	}
	if trusted.AutomationID == nil || *trusted.AutomationID != termix.ID || trusted.AutomationWatch {
		t.Fatalf("命中可信来源的告警应挂到来源上: %+v", trusted)
	}
	if watched.AutomationID == nil || *watched.AutomationID != termix.ID || !watched.AutomationWatch {
		t.Fatalf("凭据窃取类规则是高危例外，应标注来源且仍进研判: %+v", watched)
	}
	if crossGroup.AutomationID != nil || plain.AutomationID != nil {
		t.Fatalf("跨组与无登录归属的不应认成可信来源: %+v %+v", crossGroup, plain)
	}
	// 来源地址不符、来源已过期：照常告警，并进同主机同规则的普通告警
	if emit(host, "recon-marker", trustedFP, "10.1.1.99") != nil || emit(host, "recon-marker", otherFP, "10.1.1.35") != nil {
		t.Fatal("对不上的登录应并进普通告警")
	}
	if got := client.Alert.GetX(ctx, plain.ID); got.Count != 3 {
		t.Fatalf("普通告警应累计 3 次，实际 %d", got.Count)
	}

	eng := &Engine{DB: client, Rules: catalog, Window: 30 * time.Minute, MaxGraphNodes: 50}
	if err := eng.batch(ctx); err != nil {
		t.Fatal(err)
	}
	if got := client.Alert.GetX(ctx, trusted.ID); got.IncidentID != nil {
		t.Fatal("可信来源的告警不应进 incident")
	}
	for name, a := range map[string]*ent.Alert{"高危例外": watched, "跨组": crossGroup, "无登录归属": plain} {
		if got := client.Alert.GetX(ctx, a.ID); got.IncidentID == nil {
			t.Fatalf("%s的告警应照常进 incident", name)
		}
	}
	if got := client.TrustedSource.GetX(ctx, termix.ID); got.MatchedCount != 2 || got.LastMatchedAt == nil {
		t.Fatalf("命中计数应为 2: %+v", got)
	}

	// 撤销后立即恢复照常告警，已挂上的告警保留来源
	client.TrustedSource.UpdateOneID(termix.ID).SetRevokedAt(time.Now()).SetRevokedBy("lead").ExecX(ctx)
	if a := emit(host, "dump-marker", trustedFP, "10.1.1.35"); a == nil || a.AutomationID != nil {
		t.Fatalf("撤销后不应再认: %+v", a)
	}
	if n := client.Alert.Query().Where(alert.AutomationIDEQ(termix.ID)).CountX(ctx); n != 2 {
		t.Fatalf("撤销前挂上的 2 条告警应保留来源，实际 %d", n)
	}
}
