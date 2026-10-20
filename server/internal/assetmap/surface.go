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
	AssetID  uuid.UUID `json:"assetId"`
	Hostname string    `json:"hostname"`
	Zone     Zone      `json:"zone"`
	Level    string    `json:"level"`
	Proto    string    `json:"proto"`
	Addrs    []string  `json:"addrs"`
	Port     int       `json:"port"`
	Process  string    `json:"process,omitempty"`
	// Package 服务进程所属的包，前端据此对上这台资产的漏洞
	Package     string  `json:"package,omitempty"`
	Service     Service `json:"service"`
	Criticality *int    `json:"criticality,omitempty"`
	Score       int     `json:"score"`
	// 观测到的访问来源（主机名或 IP），公网来源是实际被外部访问的证据
	Peers      []string `json:"peers"`
	PeerCount  int      `json:"peerCount"`
	FromPublic bool     `json:"fromPublic"`
	// 服务说明（AI 识别、调查结论或人工），有则覆盖端口推测的服务名与风险
	Note *ServiceNote `json:"note,omitempty"`
}

// SurfacePeer 攻击面图上的访问方：本组资产、未纳管地址、别组资产或互联网
type SurfacePeer struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Kind  string `json:"kind"` // asset / discovered / managed / internet
	Zone  Zone   `json:"zone"`
}

// SurfacePath 一条观测到的访问路径：访问方 → 某台资产的某个服务
type SurfacePath struct {
	From    string    `json:"from"`
	AssetID uuid.UUID `json:"assetId"`
	Service string    `json:"service"` // 协议/端口
	Count   int64     `json:"count"`
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
	Peers     []SurfacePeer    `json:"peers"`
	Paths     []SurfacePath    `json:"paths"`
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
	s.Exposures, s.Blind, s.Peers, s.Paths = []ExposedService{}, []Blind{}, []SurfacePeer{}, []SurfacePath{}
	s.Summary.NoInventory = []string{}
	type service struct {
		ip   netip.Addr
		port int
	}
	// 每个服务的访问方，按端点聚合连接数
	type source struct {
		ep    endpoint
		count int64
	}
	peers := map[service]map[string]*source{}
	// 访问来源按地址列（公网来源要看得出具体是谁），画图的路径按节点聚合
	labels := map[service]map[string]bool{}
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
				peers[k] = map[string]*source{}
			}
			if peers[k][src.id] == nil {
				peers[k][src.id] = &source{ep: src}
			}
			peers[k][src.id].count += l.Count
			if labels[k] == nil {
				labels[k] = map[string]bool{}
			}
			labels[k][label(src)] = true
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

	peerNodes := map[string]endpoint{}
	for _, a := range g.Assets {
		if a.InventoryAt == nil {
			s.Summary.NoInventory = append(s.Summary.NoInventory, a.Hostname)
			continue
		}
		ips := parseIPs(a.IPAddrs)
		z, assetLevel := ZoneOf(a, g.Zones)
		notes := NotesOf(a)
		// 同一端口常同时绑在 0.0.0.0 和 :: 上（双栈），合成一条，地址并列
		type key struct {
			proto string
			port  int
		}
		var order []key
		groups := map[key][]Listener{}
		for _, l := range listenersOf(a) {
			if l.Loopback() {
				continue
			}
			k := key{l.Proto, l.Port}
			if groups[k] == nil {
				order = append(order, k)
			}
			groups[k] = append(groups[k], l)
		}
		for _, k := range order {
			level := assetLevel
			e := ExposedService{AssetID: a.ID, Hostname: a.Hostname, Zone: z, Proto: k.proto, Port: k.port, Criticality: a.Criticality}
			seen := map[string]*source{}
			seenLabels := map[string]bool{}
			for _, l := range groups[k] {
				e.Addrs = append(e.Addrs, l.Addr)
				e.Process = cmp.Or(e.Process, l.Process)
				e.Package = cmp.Or(e.Package, l.Package)
				addr, _ := netip.ParseAddr(l.Addr)
				if Public(addr) {
					level = ExposureInternet
				}
				// 通配地址上的服务，本机任一地址收到的连接都算它的访问来源
				bound := []netip.Addr{addr.Unmap()}
				if addr.IsUnspecified() {
					bound = ips
				}
				for _, ip := range bound {
					sk := service{ip, k.port}
					for id, src := range peers[sk] {
						if seen[id] == nil {
							seen[id] = &source{ep: src.ep}
						}
						seen[id].count += src.count
					}
					for p := range labels[sk] {
						seenLabels[p] = true
					}
					e.FromPublic = e.FromPublic || public[sk]
				}
			}
			e.Level, e.Service = level, ServiceOf(k.proto, k.port)
			if n, ok := notes[serviceKey(k.proto, k.port)]; ok {
				e.Note, e.Service.Name = &n, n.Name
				e.Service.Risk = cmp.Or(n.Risk, e.Service.Risk)
			}
			e.Score = Score(level, e.Service.Risk, a.Criticality)
			e.PeerCount = len(seenLabels)
			for p := range seenLabels {
				e.Peers = append(e.Peers, p)
			}
			for id, src := range seen {
				s.Paths = append(s.Paths, SurfacePath{From: id, AssetID: a.ID, Service: serviceKey(k.proto, k.port), Count: src.count})
				peerNodes[id] = src.ep
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
			if e.Service.Risk == "high" && level != ExposureInternal {
				s.Summary.High++
			}
		}
	}
	for id, ep := range peerNodes {
		p := SurfacePeer{ID: id, Label: label(ep)}
		switch {
		case ep.asset != nil:
			p.Kind = "asset"
			p.Zone, _ = ZoneOf(ep.asset, g.Zones)
		case id == "internet":
			p.Kind, p.Label, p.Zone = "internet", "internet", Zone{Kind: "external", Source: "auto"}
		case ep.managed:
			p.Kind, p.Zone = "managed", Classify([]netip.Addr{ep.ip}, nil, nil, g.Zones)
		default:
			p.Kind, p.Zone = "discovered", Classify([]netip.Addr{ep.ip}, nil, nil, g.Zones)
		}
		s.Peers = append(s.Peers, p)
	}
	slices.SortFunc(s.Peers, func(a, b SurfacePeer) int { return cmp.Compare(a.ID, b.ID) })
	slices.SortFunc(s.Paths, func(a, b SurfacePath) int {
		return cmp.Or(cmp.Compare(a.From, b.From), cmp.Compare(a.AssetID.String(), b.AssetID.String()), cmp.Compare(a.Service, b.Service))
	})
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
