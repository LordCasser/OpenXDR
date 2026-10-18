//go:build integration

package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/ent"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
)

func testProcessor(t *testing.T) (*Processor, *ent.Client, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("INTEGRATION_DATABASE_URL")
	if dsn == "" {
		t.Skip("INTEGRATION_DATABASE_URL 未配置")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	ctx := context.Background()
	if err := client.Schema.Create(ctx); err != nil {
		t.Fatal(err)
	}
	if err := EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	_, _ = db.Exec(`TRUNCATE alert_dedup_state, alerts, events, assets CASCADE`)
	rules := sigma.LoadDir(t.TempDir())
	return &Processor{DB: db, Rules: rules, Suppress: suppress.New(client, 0), Intel: intel.New(client, 0), DedupWindow: time.Hour}, client, db
}

func TestProcessorEventIdempotency(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	e := Envelope{Version: EnvelopeVersion, ID: uuid.New(), PartitionKey: "asset-a", Timestamp: time.Now(), ClassUID: 1007, Source: "agent", Raw: json.RawMessage(`{"process":{"name":"safe"}}`)}
	if err := p.Process(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if n, _ := client.Event.Query().Count(context.Background()); n != 1 {
		t.Fatalf("重复投递只能落一条事件，实际 %d", n)
	}
}

func TestPersistentDedupAcrossProcessors(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	dir := t.TempDir()
	rule := `title: Test
id: 11111111-1111-4111-8111-111111111111
status: test
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains: evil-marker
  condition: selection
level: high
`
	if err := os.WriteFile(filepath.Join(dir, "rule.yml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	p.Rules = sigma.LoadDir(dir)
	p2 := *p
	now := time.Now()
	base := Envelope{Version: EnvelopeVersion, PartitionKey: "asset-a", Timestamp: now, ClassUID: 1007, Source: "agent", AssetOS: "linux", Raw: json.RawMessage(`{"process":{"cmd_line":"evil-marker"}}`)}
	first := base
	first.ID = StableID(t.Name(), "1")
	second := base
	second.ID = StableID(t.Name(), "2")
	second.Timestamp = now.Add(time.Second)
	if err := p.Process(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := p2.Process(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	alerts, err := client.Alert.Query().All(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].Count != 2 {
		t.Fatalf("跨处理器应合并为一条 count=2 告警，实际 %#v", alerts)
	}
}

// 平台指令拉起的进程触发的告警挂在指令上、单独去重；标记核对不上（别的资产的、不存在的、早已结束的指令）照常告警
func TestPlatformCommandAlerts(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	ctx := context.Background()
	_, _ = db.Exec(`TRUNCATE commands CASCADE`)
	dir := t.TempDir()
	rule := `title: Test
id: 22222222-2222-4222-8222-222222222222
status: test
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains: probe-marker
  condition: selection
level: high
`
	if err := os.WriteFile(filepath.Join(dir, "rule.yml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	p.Rules = sigma.LoadDir(dir)
	asset := client.Asset.Create().SetHostname("pve1").SaveX(ctx)
	other := client.Asset.Create().SetHostname("pve2").SaveX(ctx)
	now := time.Now()
	running := client.Command.Create().SetKind("exec").SetAssetID(asset.ID).SetCreatedAt(now.Add(-time.Minute)).SaveX(ctx)
	elsewhere := client.Command.Create().SetKind("exec").SetAssetID(other.ID).SetCreatedAt(now.Add(-time.Minute)).SaveX(ctx)
	stale := client.Command.Create().SetKind("exec").SetAssetID(asset.ID).SetCreatedAt(now.Add(-3 * time.Hour)).
		SetCompletedAt(now.Add(-2 * time.Hour)).SaveX(ctx)

	for i, tag := range []string{running.ID.String(), "", uuid.NewString(), elsewhere.ID.String(), stale.ID.String()} {
		raw := `{"process":{"cmd_line":"probe-marker"}}`
		if tag != "" {
			raw = `{"process":{"cmd_line":"probe-marker"},"platform_command":{"uid":"` + tag + `"}}`
		}
		e := Envelope{Version: EnvelopeVersion, ID: StableID(t.Name(), strconv.Itoa(i)), PartitionKey: asset.ID.String(), AssetID: &asset.ID,
			Timestamp: now.Add(time.Duration(i) * time.Second), ClassUID: 1007, Source: "agent", AssetOS: "linux", Raw: json.RawMessage(raw)}
		if err := p.Process(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	alerts := client.Alert.Query().AllX(ctx)
	var tagged, plain int
	for _, a := range alerts {
		switch {
		case a.CommandID != nil && *a.CommandID == running.ID && a.Count == 1:
			tagged++
		case a.CommandID == nil && a.Count == 4:
			plain++
		default:
			t.Fatalf("意外的告警: %+v", a)
		}
	}
	if tagged != 1 || plain != 1 {
		t.Fatalf("应有一条挂在指令上的告警、一条照常告警（4 次）: %+v", alerts)
	}
}
