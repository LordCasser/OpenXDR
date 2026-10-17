package assetmap

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
)

// conn 一条网络事件的两端
type conn struct {
	src, dst netip.Addr
	port     int
	proto    string
}

// connOf 从网络事件取出两端。agent 与 sensor 的事件体同一约定：src_endpoint / dst_endpoint。
// 协议取 conn_tuple 的前缀，缺省按 tcp。
func connOf(raw json.RawMessage, tuple string) (conn, bool) {
	var body struct {
		Src struct {
			IP string `json:"ip"`
		} `json:"src_endpoint"`
		Dst struct {
			IP   string `json:"ip"`
			Port int    `json:"port"`
		} `json:"dst_endpoint"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return conn{}, false
	}
	src, err1 := netip.ParseAddr(body.Src.IP)
	dst, err2 := netip.ParseAddr(body.Dst.IP)
	if err1 != nil || err2 != nil || body.Dst.Port < 1 || body.Dst.Port > 65535 {
		return conn{}, false
	}
	proto := "tcp"
	if p, _, ok := strings.Cut(tuple, ":"); ok && (p == "tcp" || p == "udp") {
		proto = p
	}
	return conn{src.Unmap(), dst.Unmap(), body.Dst.Port, proto}, true
}

// dependency 这条连接算不算资产间的依赖。own 是上报 agent 所在资产的地址，sensor 事件为空。
//
// 回环、组播、链路本地、自己连自己都不算。另有一类要剔掉：源地址不是本机登记的地址、
// 目的又和源同在一个私网段——这是宿主机里容器之间的通信（docker 网桥），
// 不该在图上长出一台「未纳管主机」。
func dependency(c conn, own []netip.Addr) bool {
	d := c.dst
	if !d.IsValid() || d.IsLoopback() || d.IsUnspecified() || d.IsMulticast() ||
		d.IsLinkLocalUnicast() || d.IsLinkLocalMulticast() || c.src == d {
		return false
	}
	if len(own) == 0 || slices.Contains(own, c.src) || !d.IsPrivate() {
		return true
	}
	bits := 16
	if d.Is6() {
		bits = 64
	}
	srcNet, _ := c.src.Prefix(bits)
	return !srcNet.Contains(d)
}
