//go:build integration

package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/alert"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/suricata"
)

func eveEnvelope(t *testing.T, group uuid.UUID, ts time.Time, extra string) Envelope {
	t.Helper()
	return eveEnvelopePort(t, group, ts, 12345, extra)
}

func eveEnvelopePort(t *testing.T, group uuid.UUID, ts time.Time, port int, extra string) Envelope {
	t.Helper()
	raw := fmt.Sprintf(`{"timestamp":%q,"event_type":"alert","flow_id":18446744073709551610,"src_ip":"198.51.100.2","src_port":%d,"dest_ip":"10.0.0.2","dest_port":80,"proto":"TCP","alert":{"gid":1,"signature_id":100001,"rev":2,"signature":"受控测试","severity":1%s},"platform_command":{"uid":"spoofed"}}`, ts.Format(time.RFC3339Nano), port, extra)
	event, err := suricata.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return SuricataEnvelope(suricata.Origin{Observer: "edge", GroupID: group, Received: time.Now().UTC()}, event)
}

func TestSuricataIngestAndSuppression(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	group := uuid.New()
	a := client.Asset.Create().SetHostname("victim").SetGroupID(group).SetIPAddrs([]string{"10.0.0.2"}).SetFirstSeen(now.Add(-time.Hour)).SetLastSeen(now).SaveX(ctx)
	// 另一组使用相同私网 IP，不能影响本组归属。
	client.Asset.Create().SetHostname("other-group").SetGroupID(uuid.New()).SetIPAddrs([]string{"10.0.0.2"}).SaveX(ctx)
	e := eveEnvelope(t, group, now, "")
	encoded, _ := e.Marshal()
	replay, err := Unmarshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, envelope := range []Envelope{e, replay, eveEnvelope(t, group, now.Add(time.Second), "")} {
		if err := p.Process(ctx, envelope); err != nil {
			t.Fatal(err)
		}
	}
	if n := client.Event.Query().CountX(ctx); n != 2 {
		t.Fatalf("重传产生重复事件: %d", n)
	}
	got := client.Alert.Query().OnlyX(ctx)
	if got.AssetID == nil || *got.AssetID != a.ID || got.Count != 2 || got.Severity != 4 || got.Detail == nil || got.CommandID != nil {
		t.Fatalf("外部告警映射错误: %+v", got)
	}
	var flowID string
	if err := db.QueryRow(`SELECT raw->'suricata'->>'flow_id' FROM events LIMIT 1`).Scan(&flowID); err != nil || flowID != "18446744073709551610" {
		t.Fatalf("flow_id 失真: %q %v", flowID, err)
	}
	client.Suppression.Create().SetRuleID("suricata:1:100001").SetAssetID(a.ID).SetCreatedBy("test").SetConditions([]suppress.Condition{{Field: "dst_endpoint.ip", Op: "equals", Value: "10.0.0.2"}}).SaveX(ctx)
	p.Suppress.Reload(ctx)
	if err := p.Process(ctx, eveEnvelope(t, group, now.Add(2*time.Second), "")); err != nil {
		t.Fatal(err)
	}
	if got := client.Alert.GetX(ctx, got.ID); got.Count != 2 {
		t.Fatal("抑制没有生效")
	}
	if n := client.Event.Query().CountX(ctx); n != 3 {
		t.Fatal("抑制不能丢弃证据")
	}
	// 撤销后恢复告警，仍复用既有去重窗口。
	client.Suppression.Delete().ExecX(ctx)
	p.Suppress.Reload(ctx)
	if err := p.Process(ctx, eveEnvelope(t, group, now.Add(3*time.Second), "")); err != nil {
		t.Fatal(err)
	}
	if client.Alert.GetX(ctx, got.ID).Count != 3 {
		t.Fatal("撤销抑制后没有恢复")
	}
}

func TestSuricataAttributionBoundaries(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	group := uuid.New()
	a := client.Asset.Create().SetHostname("a").SetGroupID(group).SetIPAddrs([]string{"10.0.0.2"}).SetFirstSeen(now.Add(-time.Hour)).SetLastSeen(now).SaveX(ctx)
	b := client.Asset.Create().SetHostname("b").SetGroupID(group).SetIPAddrs([]string{"198.51.100.2"}).SetFirstSeen(now.Add(-time.Hour)).SetLastSeen(now).SaveX(ctx)
	// 两端均为组内资产且未声明 target：两端各落一份证据与告警，不猜谁是受影响主机；重传仍幂等。
	eastWest := eveEnvelope(t, group, now, "")
	for range 2 {
		if err := p.Process(ctx, eastWest); err != nil {
			t.Fatal(err)
		}
	}
	if n := client.Event.Query().CountX(ctx); n != 2 {
		t.Fatalf("东西向应两端各一份证据: %d", n)
	}
	for _, id := range []uuid.UUID{a.ID, b.ID} {
		if got := client.Alert.Query().Where(alert.AssetIDEQ(id)).OnlyX(ctx); got.Count != 1 {
			t.Fatalf("东西向告警归属或计数错误: %+v", got)
		}
	}
	if err := p.Process(ctx, eveEnvelope(t, group, now.Add(time.Second), `,"target":{"ip":"10.0.0.2"}`)); err != nil {
		t.Fatal(err)
	}
	if n := client.Alert.Query().Where(alert.AssetIDEQ(a.ID)).CountX(ctx); n != 1 {
		t.Fatal("target 未归属到目的主机")
	}
	// 资产转组发生在队列消费之前：不能沿用旧组归属。
	e := eveEnvelope(t, group, now.Add(2*time.Second), `,"target":{"ip":"10.0.0.2"}`)
	e.AssetID = &a.ID
	client.Asset.UpdateOneID(a.ID).SetGroupID(uuid.New()).SaveX(ctx)
	if err := p.Process(ctx, e); err != nil {
		t.Fatal(err)
	}
	if n := client.Event.Query().Where().CountX(ctx); n != 4 {
		t.Fatal(n)
	}
	stored := client.Event.GetX(ctx, e.ID)
	if stored.AssetID != nil {
		t.Fatal("排队期间转组后仍错误归属")
	}
	// 旧事件和重复 IP 不能用当前清单强行解释。
	client.Asset.Create().SetHostname("duplicate").SetGroupID(group).SetIPAddrs(b.IPAddrs).SetFirstSeen(now.Add(-time.Hour)).SetLastSeen(now).SaveX(ctx)
	for i, ts := range []time.Time{now.Add(-time.Hour), now.Add(3 * time.Second)} {
		e := eveEnvelope(t, group, ts, `,"target":{"ip":"198.51.100.2"}`)
		if err := p.Process(ctx, e); err != nil {
			t.Fatal(err)
		}
		if client.Event.GetX(ctx, e.ID).AssetID != nil {
			t.Fatalf("边界 %d 错误归属", i)
		}
	}
	// EVE 中的字段没有被提升为平台指令身份。
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(e.Raw, &raw)
	if raw["platform_command"] != nil {
		t.Fatal("接受了伪造的平台指令标记")
	}
}

// 扫描式命中换源端口不能拆成新告警；队列积压不能让实时告警失去归属。
func TestSuricataDedupAcrossPortsAndBacklog(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	group := uuid.New()
	a := client.Asset.Create().SetHostname("victim").SetGroupID(group).SetIPAddrs([]string{"10.0.0.2"}).SetFirstSeen(now.Add(-time.Hour)).SetLastSeen(now).SaveX(ctx)
	for i := range 100 {
		if err := p.Process(ctx, eveEnvelopePort(t, group, now.Add(time.Duration(i)*time.Millisecond), 20000+i, "")); err != nil {
			t.Fatal(err)
		}
	}
	got := client.Alert.Query().OnlyX(ctx)
	if got.Count != 100 || got.AssetID == nil || *got.AssetID != a.ID {
		t.Fatalf("换端口应累计到同一告警: %+v", got)
	}
	// 未归属时同样按地址对累计
	other := uuid.New()
	for i := range 10 {
		if err := p.Process(ctx, eveEnvelopePort(t, other, now.Add(time.Duration(i)*time.Millisecond), 30000+i, "")); err != nil {
			t.Fatal(err)
		}
	}
	if n := client.Alert.Query().Where(alert.AssetIDIsNil()).CountX(ctx); n != 1 {
		t.Fatalf("未归属告警按端口拆开: %d", n)
	}
	// 接收时是实时的，消费时已积压半小时：仍按事件时刻的资产观测归属
	backlog := eveEnvelopePort(t, group, now.Add(-30*time.Minute), 12345, `,"target":{"ip":"10.0.0.2"}`)
	received := *backlog.Suricata
	received.Received = backlog.Timestamp.Add(time.Second)
	backlog.Suricata = &received
	if err := p.Process(ctx, backlog); err != nil {
		t.Fatal(err)
	}
	if stored := client.Event.GetX(ctx, backlog.ID); stored.AssetID == nil || *stored.AssetID != a.ID {
		t.Fatal("队列积压导致实时告警失去归属")
	}
}
