package assetmap

import (
	"net/netip"

	"github.com/google/uuid"

	"openxdr/server/ent"
)

// Zone 资产或地址所在的网络区域。Name 为空表示自动划分，前端按 Kind 显示内置名称；
// 云上自动划分时 Name 是云厂商标识。
type Zone struct {
	ID     *uuid.UUID `json:"id,omitempty"`
	Name   string     `json:"name"`
	Kind   string     `json:"kind"`
	Source string     `json:"source"` // manual 手工指派 / cidr 网段命中 / cloud 云元数据 / auto 按 IP
}

// 暴露级别：公网可达 / 隔离区 / 仅内网
const (
	ExposureInternet = "internet"
	ExposureDMZ      = "dmz"
	ExposureInternal = "internal"
)

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Public 公网单播地址。私网、CGNAT（Tailscale 等覆盖网）、ULA、链路本地都不算
func Public(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a)
}

// Classify 区域判定，优先级：手工指派 > 组内网段（最长前缀）> 云环境 > 按 IP 公私。
func Classify(ips []netip.Addr, cloud *Cloud, manual *ent.Zone, zones []*ent.Zone) Zone {
	if manual != nil {
		return Zone{ID: &manual.ID, Name: manual.Name, Kind: string(manual.Kind), Source: "manual"}
	}
	if z := matchCIDR(ips, zones); z != nil {
		return Zone{ID: &z.ID, Name: z.Name, Kind: string(z.Kind), Source: "cidr"}
	}
	if cloud != nil {
		return Zone{Name: cloud.Provider, Kind: "cloud", Source: "cloud"}
	}
	for _, ip := range ips {
		if Public(ip) {
			return Zone{Kind: "external", Source: "auto"}
		}
	}
	return Zone{Kind: "internal", Source: "auto"}
}

func matchCIDR(ips []netip.Addr, zones []*ent.Zone) *ent.Zone {
	var best *ent.Zone
	bits := -1
	for _, z := range zones {
		for _, c := range z.Cidrs {
			p, err := netip.ParsePrefix(c)
			if err != nil || p.Bits() <= bits {
				continue
			}
			for _, ip := range ips {
				if p.Contains(ip.Unmap()) {
					best, bits = z, p.Bits()
					break
				}
			}
		}
	}
	return best
}

// Exposure 资产的暴露级别：公网区域、带公网 IP 或云上有公网地址都算公网可达。
func Exposure(z Zone, ips []netip.Addr, cloud *Cloud) string {
	if z.Kind == "external" || (cloud != nil && cloud.PublicIP != "") {
		return ExposureInternet
	}
	for _, ip := range ips {
		if Public(ip) {
			return ExposureInternet
		}
	}
	if z.Kind == "dmz" {
		return ExposureDMZ
	}
	return ExposureInternal
}

// ZoneOf 资产的区域与暴露级别。zones 是资产所在组的区域定义，手工指派的区域也在其中
func ZoneOf(a *ent.Asset, zones []*ent.Zone) (Zone, string) {
	var manual *ent.Zone
	for _, z := range zones {
		if a.ZoneID != nil && z.ID == *a.ZoneID {
			manual = z
		}
	}
	ips, cloud := parseIPs(a.IPAddrs), cloudOf(a)
	z := Classify(ips, cloud, manual, zones)
	return z, Exposure(z, ips, cloud)
}

// parseIPs 资产登记的地址串转 netip，坏值跳过
func parseIPs(raw []string) []netip.Addr {
	out := make([]netip.Addr, 0, len(raw))
	for _, s := range raw {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a.Unmap())
		}
	}
	return out
}
