package correlate

import (
	"encoding/json"
	"testing"

	"openxdr/server/ent"
)

func recurAlert(rule string, class int, raw string) *ent.Alert {
	return &ent.Alert{RuleID: rule, Edges: ent.AlertEdges{Event: &ent.Event{ClassUID: class, Raw: json.RawMessage(raw)}}}
}

// 实体键：同一件事键相同，不同实体、不同容器键不同，取不到实体为空（不参与复发归并）。
func TestRecurKey(t *testing.T) {
	inbound := `{"connection_info":{"direction":"inbound"},"src_endpoint":{"ip":"1.2.3.4"},"dst_endpoint":{"ip":"10.0.0.1"}}`
	outbound := `{"connection_info":{"direction":"outbound"},"src_endpoint":{"ip":"10.0.0.1"},"dst_endpoint":{"ip":"1.2.3.4"}}`
	same := [][2]*ent.Alert{
		{recurAlert("r", 4001, inbound), recurAlert("r", 4001, outbound)},
		{recurAlert("r", 4003, `{"query":{"hostname":"Evil.top"}}`), recurAlert("r", 4003, `{"query":{"hostname":"evil.top"}}`)},
		{recurAlert("intel:ip:1.2.3.4", 4001, `{"src_endpoint":{"ip":"1.2.3.4","port":1}}`), recurAlert("intel:ip:1.2.3.4", 4001, `{"src_endpoint":{"ip":"1.2.3.4","port":2}}`)},
	}
	for i, p := range same {
		if a, b := recurKey(p[0]), recurKey(p[1]); a == "" || a != b {
			t.Errorf("same[%d] 应同键：%q vs %q", i, a, b)
		}
	}
	differ := [][2]*ent.Alert{
		{recurAlert("r", 4003, `{"query":{"hostname":"a.top"}}`), recurAlert("r", 4003, `{"query":{"hostname":"b.top"}}`)},
		{recurAlert("r", 4003, `{"query":{"hostname":"a.top"},"container":{"uid":"203","name":"dns-primary"}}`),
			recurAlert("r", 4003, `{"query":{"hostname":"a.top"},"container":{"uid":"204","name":"dns-secondary"}}`)},
		{recurAlert("r", 1007, `{"process":{"cmd_line":"id","file":{"path":"/usr/bin/id"}}}`),
			recurAlert("r", 1007, `{"process":{"cmd_line":"id -a","file":{"path":"/usr/bin/id"}}}`)},
	}
	for i, p := range differ {
		if a, b := recurKey(p[0]), recurKey(p[1]); a == b {
			t.Errorf("differ[%d] 不应同键：%q", i, a)
		}
	}
	for i, al := range []*ent.Alert{
		{RuleID: "xdr:beacon"},
		recurAlert("r", 1007, `{}`),
		recurAlert("r", 3002, `{"user":{"name":"root"}}`),
		recurAlert("r", 4003, `garbage`),
	} {
		if k := recurKey(al); k != "" {
			t.Errorf("none[%d] 取不到实体应为空，得到 %q", i, k)
		}
	}
}
