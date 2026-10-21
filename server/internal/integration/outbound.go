package integration

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/setting"
)

// OutboundPolicy 内网目标须显式放行，域名解析后仍拒绝元数据和本机地址。
type OutboundPolicy struct {
	Hosts    []string
	Networks []netip.Prefix
}

func ParseOutboundPolicy(value string) (OutboundPolicy, error) {
	var p OutboundPolicy
	for _, raw := range strings.Split(value, ",") {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v == "" {
			continue
		}
		if network, err := netip.ParsePrefix(v); err == nil {
			p.Networks = append(p.Networks, network.Masked())
			continue
		}
		if strings.ContainsAny(v, "/:*?#@ ") {
			return p, errors.New("出站允许清单必须是精确域名或 CIDR")
		}
		p.Hosts = append(p.Hosts, v)
	}
	return p, nil
}
func ValidateTarget(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return nil, errors.New("目标必须是无凭据、查询参数和片段的 HTTPS URL")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("目标端口无效")
		}
	}
	return u, nil
}
func (p OutboundPolicy) permits(host string, ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, raw := range []string{"0.0.0.0/8", "240.0.0.0/4", "100.100.100.200/32", "64:ff9b::/96", "64:ff9b:1::/48"} {
		if netip.MustParsePrefix(raw).Contains(ip) {
			return false
		}
	}
	private := ip.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
	if !private {
		return true
	}
	for _, allowed := range p.Hosts {
		if strings.EqualFold(strings.TrimSuffix(host, "."), allowed) {
			return true
		}
	}
	for _, network := range p.Networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
func (p OutboundPolicy) transport() *http.Transport {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Transport{TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, errors.New("目标解析失败")
		}
		if len(ips) == 0 {
			return nil, errors.New("目标没有可用地址")
		}
		for _, ip := range ips {
			if !p.permits(host, ip) {
				return nil, errors.New("目标地址不在允许范围")
			}
		}
		// 使用已经验证的地址实际拨号，Transport 仍按 URL 主机名校验证书。
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}}
}
func SignEvent(secret []byte, timestamp, eventID string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp + "." + eventID + "."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

const outboundAllowKey = "integration.outbound_allow"

// OutboundAllow 内网目标放行清单。控制台保存在 settings 表；Locked 非空（环境变量
// INTEGRATION_WEBHOOK_ALLOW）时以它为准，控制台只读。每次发送前读取，改了即生效、各节点一致。
type OutboundAllow struct {
	DB     *ent.Client
	Locked string
}

// Entries 返回生效清单与是否锁定。
func (a *OutboundAllow) Entries(ctx context.Context) ([]string, bool, error) {
	if a.Locked != "" {
		return splitAllow(a.Locked), true, nil
	}
	row, err := a.DB.Setting.Get(ctx, outboundAllowKey)
	if ent.IsNotFound(err) {
		return []string{}, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var entries []string
	if err := json.Unmarshal(row.Value, &entries); err != nil {
		return nil, false, errors.New("出站允许清单配置损坏")
	}
	return entries, false, nil
}

// Policy 生效清单解析失败时报错而不是放宽：本次投递按暂时失败重试。
func (a *OutboundAllow) Policy(ctx context.Context) (OutboundPolicy, error) {
	if a == nil {
		return OutboundPolicy{}, nil
	}
	entries, _, err := a.Entries(ctx)
	if err != nil {
		return OutboundPolicy{}, err
	}
	return ParseOutboundPolicy(strings.Join(entries, ","))
}

// CleanAllow 规范化并校验清单：每项须是精确域名或 CIDR，去重，最多 200 项。
func CleanAllow(entries []string) ([]string, error) {
	clean := []string{}
	for _, raw := range entries {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v == "" || slices.Contains(clean, v) {
			continue
		}
		if p, err := ParseOutboundPolicy(v); err != nil || len(p.Hosts)+len(p.Networks) != 1 || len(v) > 253 {
			return nil, fmt.Errorf("%q 不是精确域名或 CIDR", raw)
		}
		clean = append(clean, v)
	}
	if len(clean) > 200 {
		return nil, errors.New("出站允许清单最多 200 项")
	}
	return clean, nil
}

// Save 在调用方事务内保存已校验的清单，审计由调用方写入同一事务。
func (a *OutboundAllow) Save(ctx context.Context, tx *ent.Tx, clean []string) error {
	if a.Locked != "" {
		return ErrOutboundLocked
	}
	value, err := json.Marshal(clean)
	if err != nil {
		return err
	}
	n, err := tx.Setting.Update().Where(setting.IDEQ(outboundAllowKey)).SetValue(value).Save(ctx)
	if err == nil && n == 0 {
		err = tx.Setting.Create().SetID(outboundAllowKey).SetValue(value).Exec(ctx)
	}
	return err
}

var ErrOutboundLocked = errors.New("出站允许清单由环境变量 INTEGRATION_WEBHOOK_ALLOW 锁定")

func splitAllow(value string) []string {
	out := []string{}
	for _, v := range strings.Split(value, ",") {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			out = append(out, v)
		}
	}
	return out
}
