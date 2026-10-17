//go:build integration

package assetmap

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/assetlink"
	"openxdr/server/internal/testdb"
	"openxdr/server/internal/triage"
)

// 网络事件聚合成依赖边、设备清单物化到资产，游标落库后重跑不重复计数；
// 图谱与攻击面基于物化结果给出正确的对端与暴露面。
func TestEngineMaterializesLinksAndInventory(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	group, err := client.Group.Create().SetName("prod").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	web, _ := client.Asset.Create().SetHostname("web-01").SetIPAddrs([]string{"10.0.0.1"}).SetGroupID(group.ID).Save(ctx)
	dbHost, _ := client.Asset.Create().SetHostname("db-01").SetIPAddrs([]string{"10.0.0.2"}).SetGroupID(group.ID).Save(ctx)

	now := time.Now()
	guid := uuid.New()
	mustEvent := func(c *ent.EventCreate) {
		if _, err := c.Save(ctx); err != nil {
			t.Fatal(err)
		}
	}
	mustEvent(client.Event.Create().SetTs(now.Add(-5 * time.Minute)).SetClassUID(1007).SetSource("agent").SetAssetID(web.ID).
		SetProcessGUID(guid).SetRaw(json.RawMessage(`{"process":{"name":"nginx"}}`)))
	for i := range 3 {
		mustEvent(client.Event.Create().SetTs(now.Add(-time.Duration(4-i) * time.Minute)).SetClassUID(classNetwork).SetSource("agent").
			SetAssetID(web.ID).SetProcessGUID(guid).SetConnTuple("tcp:10.0.0.1:40000>10.0.0.2:5432").
			SetRaw(json.RawMessage(`{"src_endpoint":{"ip":"10.0.0.1","port":40000},"dst_endpoint":{"ip":"10.0.0.2","port":5432}}`)))
	}
	// 同一网桥上的容器互连，不该成为依赖
	mustEvent(client.Event.Create().SetTs(now.Add(-time.Minute)).SetClassUID(classNetwork).SetSource("agent").SetAssetID(web.ID).
		SetRaw(json.RawMessage(`{"src_endpoint":{"ip":"172.18.0.3","port":1},"dst_endpoint":{"ip":"172.18.0.4","port":6379}}`)))
	inv := `{"activity_id":2,"device":{"listening":[{"proto":"tcp","addr":"0.0.0.0","port":5432,"process":{"pid":9,"name":"postgres"}}]}}`
	mustEvent(client.Event.Create().SetTs(now.Add(-30 * time.Second)).SetClassUID(ClassInventory).SetSource("agent").SetAssetID(dbHost.ID).SetRaw(json.RawMessage(inv)))
	// 更早的快照乱序到达，不能覆盖新的
	mustEvent(client.Event.Create().SetTs(now.Add(-40 * time.Second)).SetClassUID(ClassInventory).SetSource("agent").SetAssetID(dbHost.ID).
		SetRaw(json.RawMessage(`{"device":{"listening":[]}}`)))

	e := &Engine{DB: client, SQL: db, Interval: time.Second}
	e.cursor = e.loadCursor(ctx)
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	links, err := client.AssetLink.Query().All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].Count != 3 || links[0].Process != "nginx" || links[0].DstPort != 5432 || *links[0].SrcAssetID != web.ID {
		t.Fatalf("依赖边: %+v", links)
	}
	got, _ := client.Asset.Get(ctx, dbHost.ID)
	if got.InventoryAt == nil || len(listenersOf(got)) != 1 {
		t.Fatalf("清单物化: %s", got.Listening)
	}

	// 游标已落库：新引擎实例接着扫，不重复计数
	mustEvent(client.Event.Create().SetTs(now).SetClassUID(classNetwork).SetSource("agent").SetAssetID(web.ID).SetProcessGUID(guid).
		SetRaw(json.RawMessage(`{"src_endpoint":{"ip":"10.0.0.1","port":40001},"dst_endpoint":{"ip":"10.0.0.2","port":5432}}`)))
	e2 := &Engine{DB: client, SQL: db, Interval: time.Second}
	e2.cursor = e2.loadCursor(ctx)
	if n, err := e2.batch(ctx); err != nil || n != 1 {
		t.Fatalf("续扫应只读到新事件: n=%d err=%v", n, err)
	}
	if l, _ := client.AssetLink.Query().Where(assetlink.DstPortEQ(5432)).Only(ctx); l.Count != 4 {
		t.Fatalf("续扫计数: %d", l.Count)
	}

	g, err := LoadGroup(ctx, client, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	graph := g.Graph(now)
	if len(graph.Nodes) != 2 || len(graph.Edges) != 1 || graph.Edges[0].Processes[0] != "nginx" {
		t.Fatalf("图谱: %+v", graph)
	}
	s := g.Surface()
	if len(s.Exposures) != 1 || s.Exposures[0].Peers[0] != "web-01" || len(s.Summary.NoInventory) != 1 {
		t.Fatalf("攻击面: %+v", s)
	}
}

// 清单到了的新资产当轮标注；人工锁定的字段不被覆盖；编造的对端被丢弃；
// 模型输出坏了不写入、隔一个周期再试。
func TestAnnotateRespectsLocksAndFacts(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	reply := `{"role":"PostgreSQL 数据库","summary":"业务主库","criticality":5,"reason":"被应用依赖","relations":[{"peer":"web-01","note":"读写业务库"},{"peer":"ghost","note":"编造"}]}`
	calls := 0
	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": reply}}}})
	}))
	t.Cleanup(llm.Close)

	now := time.Now()
	web, _ := client.Asset.Create().SetHostname("web-01").SetIPAddrs([]string{"10.0.0.1"}).Save(ctx)
	dbHost, _ := client.Asset.Create().SetHostname("db-01").SetIPAddrs([]string{"10.0.0.2"}).SetInventoryAt(now).
		SetListening(json.RawMessage(`[{"proto":"tcp","addr":"0.0.0.0","port":5432,"process":"postgres"}]`)).
		SetRole("人工定的角色").SetLockedFields([]string{"role"}).Save(ctx)
	client.AssetLink.Create().SetSrcIP("10.0.0.1").SetSrcAssetID(web.ID).SetDstIP("10.0.0.2").SetDstPort(5432).SetProto("tcp").
		SetCount(3).SetFirstSeen(now).SetLastSeen(now).SaveX(ctx)

	e := &Engine{DB: client, SQL: db, LLM: triage.NewLLM(llm.URL, "fake", "", 5*time.Second), Interval: time.Second}
	e.annotateDue(ctx)
	got := client.Asset.GetX(ctx, dbHost.ID)
	if *got.Role != "人工定的角色" || *got.Criticality != 5 || got.AnnotatedAt == nil {
		t.Fatalf("锁定字段不能被覆盖，其余照写: role=%v crit=%v", *got.Role, got.Criticality)
	}
	if got.RelationNotes["web-01"] != "读写业务库" || len(got.RelationNotes) != 1 {
		t.Fatalf("只保留事实里出现过的对端: %v", got.RelationNotes)
	}
	if w := client.Asset.GetX(ctx, web.ID); w.AnnotatedAt != nil {
		t.Fatal("清单还没到的新资产先不标注")
	}

	// 坏输出：不写入，且在一个检查周期内不再重试
	reply = "抱歉，我无法判断"
	client.Asset.UpdateOneID(web.ID).SetInventoryAt(now).ExecX(ctx)
	before := calls
	e.annotateDue(ctx)
	e.annotateDue(ctx)
	if calls != before+1 || client.Asset.GetX(ctx, web.ID).Role != nil {
		t.Fatalf("坏输出不写入且退避: calls %d→%d", before, calls)
	}
}
