//go:build integration

package correlate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/ingest"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/suricata"
	"openxdr/server/internal/testdb"
)

func TestSuricataHTTPToIncident(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := ingest.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM alert_dedup_state"); err != nil {
		t.Fatal(err)
	}
	rules := &sigma.Engine{}
	p := &ingest.Processor{DB: db, Rules: rules, Suppress: suppress.New(client, 0), Intel: intel.New(client, 0), DedupWindow: time.Minute}
	group := uuid.New()
	now := time.Now().UTC()
	a := client.Asset.Create().SetHostname("target").SetGroupID(group).SetIPAddrs([]string{"10.0.0.2"}).SetFirstSeen(now.Add(-time.Hour)).SetLastSeen(now).SaveX(ctx)
	process := uuid.New()
	endpoint := client.Event.Create().SetTs(now.Add(-time.Second)).SetClassUID(1007).SetSource("agent").SetAssetID(a.ID).SetProcessGUID(process).SetRaw(json.RawMessage(`{"process":{"name":"test-process","cmd_line":"controlled-test"}}`)).SaveX(ctx)
	client.Alert.Create().SetTs(endpoint.Ts).SetAssetID(a.ID).SetEventID(endpoint.ID).SetRuleID("endpoint-test").SetSeverity(3).SaveX(ctx)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		suricata.Accept(w, r, suricata.Origin{Observer: "edge", GroupID: group}, func(ctx context.Context, origin suricata.Origin, event suricata.Event) error {
			return p.Process(ctx, ingest.SuricataEnvelope(origin, event))
		}, func(status int, message string) { http.Error(w, message, status) })
	})
	raw := fmt.Sprintf(`{"timestamp":%q,"event_type":"alert","flow_id":42,"src_ip":"198.51.100.2","src_port":12345,"dest_ip":"10.0.0.2","dest_port":80,"proto":"TCP","alert":{"gid":1,"signature_id":100001,"rev":2,"signature":"受控网络告警","severity":1}}`, now.Format(time.RFC3339Nano))
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("POST", "/api/integration/v1/suricata/events", strings.NewReader(raw))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 202 {
			t.Fatalf("接入失败: %d %s", w.Code, w.Body.String())
		}
	}
	engine := &Engine{DB: client, Rules: rules, Window: 5 * time.Minute, MaxGraphNodes: 50}
	if err := engine.batch(ctx); err != nil {
		t.Fatal(err)
	}
	incs := client.Incident.Query().AllX(ctx)
	if len(incs) != 1 {
		t.Fatalf("网络与端点告警没有归入同一事件: %d", len(incs))
	}
	alerts := client.Alert.Query().AllX(ctx)
	if len(alerts) != 2 {
		t.Fatalf("重传生成了重复告警: %d", len(alerts))
	}
	for _, al := range alerts {
		if al.IncidentID == nil || *al.IncidentID != incs[0].ID {
			t.Fatal("关联不一致")
		}
	}
	if !strings.Contains(string(incs[0].Graph), "connection") || !strings.Contains(string(incs[0].Graph), process.String()) || !strings.Contains(*incs[0].Title, "受控网络告警") {
		t.Fatalf("关系图缺证据或标题: %s", incs[0].Graph)
	}
}

// 东西向告警两端各一条，同一批里也要经横向关联归入同一 incident。
func TestSuricataEastWestOneIncident(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := ingest.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM alert_dedup_state"); err != nil {
		t.Fatal(err)
	}
	rules := &sigma.Engine{}
	p := &ingest.Processor{DB: db, Rules: rules, Suppress: suppress.New(client, 0), Intel: intel.New(client, 0), DedupWindow: time.Minute}
	group := uuid.New()
	now := time.Now().UTC()
	for host, ip := range map[string]string{"src": "10.0.0.1", "dst": "10.0.0.2"} {
		client.Asset.Create().SetHostname(host).SetGroupID(group).SetIPAddrs([]string{ip}).SetFirstSeen(now.Add(-time.Hour)).SetLastSeen(now).SaveX(ctx)
	}
	event, err := suricata.Parse([]byte(fmt.Sprintf(`{"timestamp":%q,"event_type":"alert","src_ip":"10.0.0.1","src_port":40000,"dest_ip":"10.0.0.2","dest_port":445,"proto":"TCP","alert":{"gid":1,"signature_id":100002,"rev":1,"signature":"受控横向告警","severity":1}}`, now.Format(time.RFC3339Nano))))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(ctx, ingest.SuricataEnvelope(suricata.Origin{Observer: "edge", GroupID: group, Received: now}, event)); err != nil {
		t.Fatal(err)
	}
	engine := &Engine{DB: client, Rules: rules, Window: 5 * time.Minute, MaxGraphNodes: 50}
	if err := engine.batch(ctx); err != nil {
		t.Fatal(err)
	}
	if n := client.Alert.Query().CountX(ctx); n != 2 {
		t.Fatalf("两端应各一条告警: %d", n)
	}
	if n := client.Incident.Query().CountX(ctx); n != 1 {
		t.Fatalf("东西向告警被拆成 %d 个 incident", n)
	}
}

func TestSuricataUnknownIsolation(t *testing.T) {
	ctx, client := testdb.New(t)
	engine := &Engine{DB: client, Rules: &sigma.Engine{}, Window: 5 * time.Minute, MaxGraphNodes: 50}
	now := time.Now()
	makeAlert := func(source, scope string, ts time.Time) *ent.Alert {
		raw, _ := json.Marshal(map[string]any{"metadata": map[string]string{"suricata_scope": scope}})
		event := client.Event.Create().SetTs(ts).SetClassUID(2004).SetSource(source).SetRaw(raw).SaveX(ctx)
		return client.Alert.Create().SetTs(ts).SetRuleID("suricata:1:1").SetSeverity(3).SetEventID(event.ID).SaveX(ctx)
	}
	a := makeAlert("suricata", "group-a|edge|tuple", now)
	b := makeAlert("suricata", "group-b|edge|tuple", now)
	c := makeAlert("syslog", "", now)
	if err := engine.batch(ctx); err != nil {
		t.Fatal(err)
	}
	if n := client.Incident.Query().CountX(ctx); n != 3 {
		t.Fatalf("未知资产跨来源或组串联: %d", n)
	}
	next := makeAlert("suricata", "group-a|edge|tuple", now.Add(time.Second))
	if err := engine.batch(ctx); err != nil {
		t.Fatal(err)
	}
	a, b, c, next = client.Alert.GetX(ctx, a.ID), client.Alert.GetX(ctx, b.ID), client.Alert.GetX(ctx, c.ID), client.Alert.GetX(ctx, next.ID)
	if *a.IncidentID != *next.IncidentID || *a.IncidentID == *b.IncidentID || *a.IncidentID == *c.IncidentID {
		t.Fatal("跨批次的未知归属不正确")
	}
}

func TestSuricataLateralGroupIsolation(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()
	source := client.Asset.Create().SetHostname("source").SetGroupID(uuid.New()).SetIPAddrs([]string{"10.0.0.1"}).SaveX(ctx)
	target := client.Asset.Create().SetHostname("target").SetGroupID(uuid.New()).SetIPAddrs([]string{"10.0.0.2"}).SaveX(ctx)
	inc := client.Incident.Create().SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	conn := client.Event.Create().SetTs(now).SetClassUID(2004).SetSource("suricata").SetAssetID(source.ID).SetConnTuple("tcp:10.0.0.1:12345>10.0.0.2:80").SetRaw(json.RawMessage(`{}`)).SaveX(ctx)
	client.Alert.Create().SetTs(now).SetRuleID("suricata:1:1").SetSeverity(4).SetEventID(conn.ID).SetAssetID(source.ID).SetIncidentID(inc.ID).SaveX(ctx)
	al := &ent.Alert{Ts: now.Add(time.Second), AssetID: &target.ID, Edges: ent.AlertEdges{Asset: target}}
	engine := &Engine{DB: client, Rules: &sigma.Engine{}, Window: 5 * time.Minute}
	if _, _, err := engine.findByLateral(ctx, al, nil); err == nil {
		t.Fatal("跨组同地址不应关联")
	}
	// 同样证据在同组内仍可用于横向移动关联。
	target.GroupID = source.GroupID
	client.Asset.UpdateOneID(target.ID).SetGroupID(*source.GroupID).SaveX(ctx)
	if got, _, err := engine.findByLateral(ctx, al, nil); err != nil || got.ID != inc.ID {
		t.Fatalf("同组关联失效: %v", err)
	}
}
