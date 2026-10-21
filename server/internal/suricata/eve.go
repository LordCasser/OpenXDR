// Package suricata 接收 EVE 告警，不执行或转换 Suricata 规则。
package suricata

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

var protoName = regexp.MustCompile(`^[a-z0-9-]{1,16}$`)

// Origin 只能由持有接入配置的服务端设置，不能从 EVE 报文取值。
// Received 是接入节点确认收到的时刻，用来区分探针迟到和平台队列积压。
type Origin struct {
	Observer string    `json:"observer"`
	GroupID  uuid.UUID `json:"group_id"`
	Received time.Time `json:"received_at"`
}

type Alert struct {
	GID       uint32    `json:"gid"`
	SID       uint32    `json:"signature_id"`
	Rev       uint32    `json:"rev"`
	Signature string    `json:"signature"`
	Severity  int       `json:"severity"`
	Source    *Endpoint `json:"source,omitempty"`
	Target    *Endpoint `json:"target,omitempty"`
}

type Endpoint struct {
	IP string `json:"ip"`
}

type Event struct {
	Timestamp string          `json:"timestamp"`
	EventType string          `json:"event_type"`
	FlowID    json.Number     `json:"flow_id"`
	SrcIP     string          `json:"src_ip"`
	SrcPort   uint16          `json:"src_port"`
	DestIP    string          `json:"dest_ip"`
	DestPort  uint16          `json:"dest_port"`
	Proto     string          `json:"proto"`
	Alert     Alert           `json:"alert"`
	Time      time.Time       `json:"-"`
	Raw       json.RawMessage `json:"-"`
}

// Parse 校验单条告警并规范 JSON；UseNumber 避免 64 位 flow_id 经浮点数失真。
func Parse(raw []byte) (Event, error) {
	var e Event
	if err := json.Unmarshal(raw, &e); err != nil {
		return e, fmt.Errorf("EVE JSON 无效")
	}
	if e.EventType != "alert" {
		return e, fmt.Errorf("只接受 EVE alert 事件")
	}
	ts, err := time.Parse(time.RFC3339Nano, e.Timestamp)
	if err != nil {
		ts, err = time.Parse("2006-01-02T15:04:05.999999999-0700", e.Timestamp)
	}
	if err != nil {
		return e, fmt.Errorf("timestamp 必须为带时区的 RFC3339 时间")
	}
	e.Time = ts.UTC()
	if e.Time.Year() < 1 || e.Time.Year() > 9999 {
		return e, fmt.Errorf("timestamp 超出支持的年份范围")
	}
	// 资产与 sensor 都用规范写法，未压缩的 IPv6 不规范化就永远对不上
	for _, ip := range []*string{&e.SrcIP, &e.DestIP} {
		if *ip, err = canonicalIP(*ip); err != nil {
			return e, fmt.Errorf("源或目的 IP 无效")
		}
	}
	// Suricata 把 ICMPv6 写作 IPv6-ICMP；其余协议名照录，不因不认识就丢告警。
	e.Proto = strings.ToLower(e.Proto)
	if e.Proto == "ipv6-icmp" {
		e.Proto = "icmpv6"
	}
	if !protoName.MatchString(e.Proto) {
		return e, fmt.Errorf("网络协议名无效")
	}
	if e.Alert.GID == 0 || e.Alert.SID == 0 || strings.TrimSpace(e.Alert.Signature) == "" || len(e.Alert.Signature) > 1024 {
		return e, fmt.Errorf("告警缺少有效的 gid、signature_id 或 signature")
	}
	if e.Alert.Severity < 1 || e.Alert.Severity > 255 {
		return e, fmt.Errorf("告警 severity 必须为 1..255")
	}
	for _, endpoint := range []*Endpoint{e.Alert.Source, e.Alert.Target} {
		if endpoint == nil {
			continue
		}
		if endpoint.IP, err = canonicalIP(endpoint.IP); err != nil || endpoint.IP != e.SrcIP && endpoint.IP != e.DestIP {
			return e, fmt.Errorf("告警角色 IP 必须属于本连接")
		}
	}
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return e, err
	}
	e.Raw, err = json.Marshal(value)
	return e, err
}

func canonicalIP(ip string) (string, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" {
		return "", fmt.Errorf("IP 无效")
	}
	return addr.Unmap().String(), nil
}

func (e Event) RuleID() string { return fmt.Sprintf("suricata:%d:%d", e.Alert.GID, e.Alert.SID) }

// Suricata 的 1 最高，与平台的递增级别相反；4 及以后的 priority 都算最低。不凭单条签名升为 critical。
func (e Event) Severity() int16 { return int16(5 - min(e.Alert.Severity, 4)) }

// Attacker 是规则标出的发起端，未标出时取连接源端。
func (e Event) Attacker() string {
	if e.Alert.Source != nil {
		return e.Alert.Source.IP
	}
	return e.SrcIP
}

func (e Event) ConnTuple() string {
	return fmt.Sprintf("%s:%s:%d>%s:%d", e.Proto, e.SrcIP, e.SrcPort, e.DestIP, e.DestPort)
}
