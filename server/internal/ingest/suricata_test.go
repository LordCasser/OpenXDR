package ingest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/suricata"
)

func TestSuricataStableEnvelope(t *testing.T) {
	raw := []byte(`{"timestamp":"2026-10-21T10:20:30+0800","event_type":"alert","flow_id":18446744073709551610,"src_ip":"198.51.100.2","src_port":12345,"dest_ip":"10.0.0.2","dest_port":80,"proto":"TCP","alert":{"gid":1,"signature_id":100001,"rev":2,"signature":"受控测试","severity":1}}`)
	event, err := suricata.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	_ = json.Unmarshal(raw, &object)
	reformatted, _ := json.MarshalIndent(object, "", "  ")
	second, err := suricata.Parse(reformatted)
	if err != nil {
		t.Fatal(err)
	}
	origin := suricata.Origin{Observer: "edge", GroupID: uuid.New(), Received: time.Now()}
	a, b := SuricataEnvelope(origin, event), SuricataEnvelope(origin, second)
	if a.ID != b.ID {
		t.Fatal("JSON 键序和空白不能改变事件身份")
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	origin.GroupID = uuid.New()
	if a.ID == SuricataEnvelope(origin, event).ID {
		t.Fatal("不同组不能共用事件身份")
	}
	// 端口不同的同一地址对去重到一起，未归属时按发起端关联
	other, _ := suricata.Parse([]byte(strings.Replace(string(raw), `"src_port":12345`, `"src_port":23456`, 1)))
	if c := SuricataEnvelope(*a.Suricata, other); c.FingerprintSuffix != a.FingerprintSuffix || c.PartitionKey != a.PartitionKey {
		t.Fatal("源端口不能拆开去重或关联")
	}
	late := *a.Suricata
	late.Received = time.Time{}
	a.Suricata = &late
	if a.Validate() == nil {
		t.Fatal("缺接收时间应拒绝")
	}
	a.Suricata = nil
	if a.Validate() == nil {
		t.Fatal("缺可信来源应拒绝")
	}
	b.Source = "agent"
	if b.Validate() == nil {
		t.Fatal("不能混用来源")
	}
}
