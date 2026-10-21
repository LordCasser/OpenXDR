package suricata

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

const sample = `{"timestamp":"2026-10-21T10:20:30.123456+0800","flow_id":18446744073709551610,"event_type":"alert","src_ip":"198.51.100.2","src_port":12345,"dest_ip":"10.0.0.2","dest_port":80,"proto":"TCP","alert":{"gid":1,"signature_id":100001,"rev":2,"signature":"受控测试","severity":1},"community_id":"1:test"}`

func TestParseEVE(t *testing.T) {
	e, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if e.RuleID() != "suricata:1:100001" || e.Severity() != 4 || e.Time.Hour() != 2 || e.ConnTuple() != "tcp:198.51.100.2:12345>10.0.0.2:80" {
		t.Fatalf("字段映射错误: %+v", e)
	}
	if !bytes.Contains(e.Raw, []byte("18446744073709551610")) || !bytes.Contains(e.Raw, []byte("community_id")) {
		t.Fatal("原始证据失真")
	}
	for _, change := range []struct{ old, new string }{
		{`"event_type":"alert"`, `"event_type":"flow"`},
		{`"severity":1`, `"severity":0`},
		{`"dest_ip":"10.0.0.2"`, `"dest_ip":"bad"`},
		{`"dest_port":80`, `"dest_port":65536`},
		{`"gid":1`, `"gid":0`},
		{`"severity":1`, `"severity":1,"target":{"ip":"10.0.0.99"}`},
		{`+0800`, ``},
		{`2026-10-21`, `0000-10-21`},
		{`"severity":1`, `"severity":256`},
		{`"proto":"TCP"`, `"proto":"tcp;x"`},
	} {
		if _, err := Parse([]byte(strings.Replace(sample, change.old, change.new, 1))); err == nil {
			t.Errorf("应拒绝 %s", change.new)
		}
	}
	if _, err := Parse([]byte(sample + sample)); err == nil {
		t.Fatal("不能接受两条拼接 JSON")
	}
	if _, err := Parse([]byte(strings.Replace(sample, `"rev":2`, `"rev":0`, 1))); err != nil {
		t.Fatal("rev=0 合法", err)
	}
	// 真实输出：ICMPv6 写作 IPv6-ICMP，priority 可到 255，都不能拒收
	if e, err := Parse([]byte(strings.Replace(sample, `"proto":"TCP"`, `"proto":"IPv6-ICMP"`, 1))); err != nil || e.Proto != "icmpv6" {
		t.Fatal("IPv6-ICMP 应接受并规范为 icmpv6", err)
	}
	if e, err := Parse([]byte(strings.Replace(sample, `"proto":"TCP"`, `"proto":"SCTP"`, 1))); err != nil || e.Proto != "sctp" {
		t.Fatal("其他协议应照录", err)
	}
	if e, err := Parse([]byte(strings.Replace(sample, `"severity":1`, `"severity":255`, 1))); err != nil || e.Severity() != 1 {
		t.Fatal("priority 超过 4 应映射为最低级", err)
	}
	full := strings.NewReplacer(`"198.51.100.2"`, `"2001:0db8:0000:0000:0000:0000:0000:0002"`, `"10.0.0.2"`, `"::ffff:10.0.0.2"`, `"severity":1`, `"severity":1,"target":{"ip":"::ffff:10.0.0.2"}`).Replace(sample)
	if e, err := Parse([]byte(full)); err != nil || e.SrcIP != "2001:db8::2" || e.DestIP != "10.0.0.2" || e.Alert.Target.IP != "10.0.0.2" {
		t.Fatalf("IP 未规范化: %+v %v", e, err)
	}
	for i := 1; i <= 4; i++ {
		e, err := Parse([]byte(strings.Replace(sample, `"severity":1`, fmt.Sprintf(`"severity":%d`, i), 1)))
		if err != nil || e.Severity() != int16(5-i) {
			t.Fatalf("severity %d 映射错误", i)
		}
	}
}

func TestAccept(t *testing.T) {
	origin := Origin{Observer: "edge", GroupID: uuid.New()}
	calls := 0
	var failure error
	publish := func(_ context.Context, got Origin, event Event) error {
		calls++
		if got.Observer != origin.Observer || got.GroupID != origin.GroupID || got.Received.IsZero() || event.Alert.SID != 100001 {
			t.Fatal("可信来源不正确")
		}
		return failure
	}
	for _, tc := range []struct {
		body   string
		status int
		calls  int
	}{
		{"{}", 400, 0},
		{strings.Repeat("x", MaxEventBytes+1), 413, 0},
		{sample, 202, 1},
	} {
		w := httptest.NewRecorder()
		status := 0
		Accept(w, httptest.NewRequest("POST", "/", strings.NewReader(tc.body)), origin, publish, func(code int, _ string) { status = code })
		if status == 0 {
			status = w.Code
		}
		if status != tc.status || calls != tc.calls {
			t.Fatalf("status=%d calls=%d", status, calls)
		}
	}
	failure = errors.New("队列不可用")
	status := 0
	Accept(httptest.NewRecorder(), httptest.NewRequest("POST", "/", strings.NewReader(sample)), origin, publish, func(code int, _ string) { status = code })
	if status != 503 {
		t.Fatal("队列失败不能确认成功")
	}
}
