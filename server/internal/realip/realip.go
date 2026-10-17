// Package realip 经反向代理时还原客户端地址。
//
// 登录退避与审计都按 RemoteAddr 记来源；不还原的话所有人都是代理的地址——
// 一人输错密码全员被退避，审计也看不出是谁。只采信可信代理转来的 X-Forwarded-For，
// 并从右往左取第一个不可信地址：客户端自己塞进去的值只会出现在左边，伪造不了。
// 没配可信代理时原样放行，不读这个头。
package realip

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Parse 解析逗号分隔的 CIDR 或单个地址。
func Parse(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range strings.Split(list, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			addr, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("可信代理地址无效：%s", s)
			}
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("可信代理网段无效：%s", s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// Middleware 来自可信代理的请求，把 RemoteAddr 换成还原出的客户端地址。
func Middleware(trusted []netip.Prefix, next http.Handler) http.Handler {
	if len(trusted) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ip := resolve(r.RemoteAddr, r.Header.Values("X-Forwarded-For"), trusted); ip != "" {
			r.RemoteAddr = net.JoinHostPort(ip, "0")
		}
		next.ServeHTTP(w, r)
	})
}

// resolve 返回还原出的客户端地址；直连方不是可信代理时返回空，保持原样。
func resolve(remote string, xff []string, trusted []netip.Prefix) string {
	if !isTrusted(hostOf(remote), trusted) {
		return ""
	}
	var hops []string
	for _, h := range xff {
		hops = append(hops, strings.Split(h, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		addr, err := netip.ParseAddr(hop)
		if err != nil {
			return "" // 链路被篡改成非地址，宁可不还原
		}
		if !isTrusted(addr, trusted) {
			return addr.Unmap().String()
		}
	}
	return ""
}

func hostOf(remote string) netip.Addr {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	addr, _ := netip.ParseAddr(host)
	return addr
}

func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
