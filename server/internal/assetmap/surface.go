package assetmap

import (
	"cmp"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
)

// ExposedService 一个对外监听的服务：在哪台资产、哪个区域、暴露到什么程度、谁连过
type ExposedService struct {
	AssetID     uuid.UUID `json:"assetId"`
	Hostname    string    `json:"hostname"`
	Zone        Zone      `json:"zone"`
	Level       string    `json:"level"`
	Proto       string    `json:"proto"`
	Addr        string    `json:"addr"`
	Port        int       `json:"port"`
	Process     string    `json:"process,omitempty"`
	Service     Service   `json:"service"`
	Criticality *int      `json:"criticality,omitempty"`
	Score       int       `json:"score"`
	// 观测到的访问来源（主机名或 IP），公网来源是实际被外部访问的证据
	Peers      []string `json:"peers"`
	PeerCount  int      `json:"peerCount"`
	FromPublic bool     `json:"fromPublic"`
}

// Blind 盲区：与本组资产有往来、却没有纳管的内网地址。
// Ports 是它被本组连过的端口，Accessed 是它访问过的本组服务
type Blind struct {
	IP       string    `json:"ip"`
	Zone     Zone      `json:"zone"`
	Ports    []string  `json:"ports"`
	Accessed []string  `json:"accessed"`
	SeenBy   []string  `json:"seenBy"`
	Count    int64     `json:"count"`
	LastSeen time.Time `json:"lastSeen"`
}

type Surface struct {
	Summary struct {
		Internet int `json:"internet"`
		DMZ      int `json:"dmz"`
		Internal int `json:"internal"`
		High     int `json:"high"`
		Blind    int `json:"blind"`
		// 还没上报监听端口的资产（旧版 agent 或刚接入），攻击面对它们是空的
		NoInventory []string `json:"noInventory"`
	} `json:"summary"`
	Exposures []ExposedService `json:"exposures"`
	Blind     []Blind          `json:"blind"`
}

var levelWeight = map[string]int{ExposureInternet: 20, ExposureDMZ: 6, ExposureInternal: 2}
var riskWeight = map[string]int{"high": 3, "medium": 2, "low": 1}

// Score 暴露级别 × 端口风险 × 重要程度（未标注按 3）
func Score(level, risk string, criticality *int) int {
	c := 3
	if criticality != nil {
		c = *criticality
	}
	return levelWeight[level] * riskWeight[risk] * c
}

// Surface 非回环监听逐个算暴露面；绑在具体公网地址上的直接算公网可达
func (g *Group) Surface() Surface {
	var s Surface
	s.Exposures, s.Blind = []ExposedService{}, []Blind{}
	s.Summary.NoInventory = []string{}
	type service struct {
		ip   netip.Addr
		port int
	}
	peers := map[service]map[string]bool{}
	public := map[service]bool{}
	blind := map[string]*Blind{}
	// unmanaged 未纳管的内网地址：公网、别组资产都不算盲区
	unmanaged := func(ep endpoint) bool { return ep.asset == nil && ep.id != "internet" && !ep.managed }
	touch := func(ep, peer endpoint, l *ent.AssetLink) *Blind {
		b := blind[ep.ip.String()]
		if b == nil {
			b = &Blind{IP: ep.ip.String(), Zone: Classify([]netip.Addr{ep.ip}, nil, nil, g.Zones), Ports: []string{}, Accessed: []string{}}
			blind[b.IP] = b
		}
		if !slices.Contains(b.SeenBy, peer.asset.Hostname) {
			b.SeenBy = append(b.SeenBy, peer.asset.Hostname)
		}
		b.Count += l.Count
		if l.LastSeen.After(b.LastSeen) {
			b.LastSeen = l.LastSeen
		}
		return b
	}
	add := func(list []string, v string) []string {
		if slices.Contains(list, v) {
			return list
		}
		return append(list, v)
	}
	for _, l := range g.Links {
		src, dst := g.resolve(l.SrcIP, l.SrcAssetID), g.resolve(l.DstIP, nil)
		port := l.Proto + "/" + strconv.Itoa(l.DstPort)
		if dst.asset != nil {
			k := service{dst.ip, l.DstPort}
			if peers[k] == nil {
				peers[k] = map[string]bool{}
			}
			peers[k][label(src)] = true
			public[k] = public[k] || src.id == "internet"
			if unmanaged(src) {
				b := touch(src, dst, l)
				b.Accessed = add(b.Accessed, dst.asset.Hostname+":"+strconv.Itoa(l.DstPort))
			}
			continue
		}
		if src.asset != nil && unmanaged(dst) {
			b := touch(dst, src, l)
			b.Ports = add(b.Ports, port)
		}
	}

	for _, a := range g.Assets {
		if a.InventoryAt == nil {
			s.Summary.NoInventory = append(s.Summary.NoInventory, a.Hostname)
			continue
		}
		ips := parseIPs(a.IPAddrs)
		z, assetLevel := ZoneOf(a, g.Zones)
		for _, l := range listenersOf(a) {
			if l.Loopback() {
				continue
			}
			level := assetLevel
			addr, _ := netip.ParseAddr(l.Addr)
			if Public(addr) {
				level = ExposureInternet
			}
			// 通配地址上的服务，本机任一地址收到的连接都算它的访问来源
			bound := []netip.Addr{addr.Unmap()}
			if addr.IsUnspecified() {
				bound = ips
			}
			seen := map[string]bool{}
			fromPublic := false
			for _, ip := range bound {
				k := service{ip, l.Port}
				for p := range peers[k] {
					seen[p] = true
				}
				fromPublic = fromPublic || public[k]
			}
			svc := ServiceOf(l.Proto, l.Port)
			e := ExposedService{AssetID: a.ID, Hostname: a.Hostname, Zone: z, Level: level,
				Proto: l.Proto, Addr: l.Addr, Port: l.Port, Process: l.Process, Service: svc,
				Criticality: a.Criticality, Score: Score(level, svc.Risk, a.Criticality),
				PeerCount: len(seen), FromPublic: fromPublic}
			for p := range seen {
				e.Peers = append(e.Peers, p)
			}
			slices.Sort(e.Peers)
			e.Peers = e.Peers[:min(len(e.Peers), 10)]
			s.Exposures = append(s.Exposures, e)
			switch level {
			case ExposureInternet:
				s.Summary.Internet++
			case ExposureDMZ:
				s.Summary.DMZ++
			default:
				s.Summary.Internal++
			}
			if svc.Risk == "high" && level != ExposureInternal {
				s.Summary.High++
			}
		}
	}
	slices.SortFunc(s.Exposures, func(a, b ExposedService) int {
		return cmp.Or(cmp.Compare(b.Score, a.Score), cmp.Compare(a.Hostname, b.Hostname), cmp.Compare(a.Port, b.Port))
	})
	for _, b := range blind {
		slices.Sort(b.Ports)
		slices.Sort(b.Accessed)
		slices.Sort(b.SeenBy)
		s.Blind = append(s.Blind, *b)
	}
	slices.SortFunc(s.Blind, func(a, b Blind) int { return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.IP, b.IP)) })
	s.Summary.Blind = len(s.Blind)
	return s
}

// label 本组资产用主机名，其余只露 IP
func label(ep endpoint) string {
	if ep.asset != nil {
		return ep.asset.Hostname
	}
	return ep.ip.String()
}
