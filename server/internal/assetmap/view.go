package assetmap

import (
	"cmp"
	"context"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/assetlink"
	"openxdr/server/ent/zone"
)

// Group 一个组的图谱原料：本组资产、区域定义、触及本组资产的依赖边
type Group struct {
	World  *World
	Assets []*ent.Asset
	Zones  []*ent.Zone
	Links  []*ent.AssetLink
}

// LoadGroup 只取最近 linkTTL 内还出现过的边
func LoadGroup(ctx context.Context, db *ent.Client, groupID uuid.UUID) (*Group, error) {
	w, err := LoadWorld(ctx, db)
	if err != nil {
		return nil, err
	}
	g := &Group{World: w}
	var ids []uuid.UUID
	var ips []string
	for _, a := range w.Assets {
		if a.GroupID != nil && *a.GroupID == groupID {
			g.Assets = append(g.Assets, a)
			ids = append(ids, a.ID)
			ips = append(ips, a.IPAddrs...)
		}
	}
	if g.Zones, err = db.Zone.Query().Where(zone.GroupIDEQ(groupID)).Order(ent.Asc(zone.FieldName)).All(ctx); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return g, nil
	}
	g.Links, err = db.AssetLink.Query().Where(
		assetlink.LastSeenGT(time.Now().Add(-linkTTL)),
		assetlink.Or(assetlink.SrcAssetIDIn(ids...), assetlink.SrcIPIn(ips...), assetlink.DstIPIn(ips...)),
	).All(ctx)
	return g, err
}

func (g *Group) inGroup(a *ent.Asset) bool {
	return a != nil && slices.Contains(g.Assets, a)
}

// endpoint 解析一端：本组资产 / 别组资产 / 未纳管内网地址 / 公网
type endpoint struct {
	id    string
	asset *ent.Asset // 仅本组资产
	ip    netip.Addr
	// 别组的已纳管资产：不是盲区，但也不露主机名
	managed bool
}

func (g *Group) resolve(ip string, assetID *uuid.UUID) endpoint {
	addr, _ := netip.ParseAddr(ip)
	a := g.World.ByID[ptr(assetID)]
	if a == nil {
		a = g.World.ByIP[addr]
	}
	switch {
	case g.inGroup(a):
		return endpoint{id: a.ID.String(), asset: a, ip: addr}
	case a == nil && Public(addr):
		return endpoint{id: "internet", ip: addr}
	default:
		// 别组资产与未纳管地址一样只露 IP，不跨组泄露主机名
		return endpoint{id: "ip:" + addr.String(), ip: addr, managed: a != nil}
	}
}

// Node 图谱节点
type Node struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"` // asset / discovered 未纳管 / managed 别组资产 / internet
	Label       string   `json:"label"`
	Zone        Zone     `json:"zone"`
	Exposure    string   `json:"exposure,omitempty"`
	Role        *string  `json:"role,omitempty"`
	Criticality *int     `json:"criticality,omitempty"`
	OS          *string  `json:"os,omitempty"`
	Online      bool     `json:"online,omitempty"`
	Listening   int      `json:"listening,omitempty"`
	Ports       []string `json:"ports,omitempty"` // 未纳管地址上被连过的端口
}

// Edge 图谱边：同一对节点的连接合并，端口与进程去重
type Edge struct {
	From      string    `json:"from"`
	To        string    `json:"to"`
	Ports     []string  `json:"ports"`
	Processes []string  `json:"processes"`
	Count     int64     `json:"count"`
	LastSeen  time.Time `json:"lastSeen"`
	Note      string    `json:"note,omitempty"`
	// 连公网的边列出最常去的目的地址
	Targets []string `json:"targets,omitempty"`
}

type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

const maxDiscovered = 300

// Graph 本组资产、它们连过或被连过的未纳管地址，公网收拢成一个节点
func (g *Group) Graph(now time.Time) Graph {
	nodes := map[string]*Node{}
	for _, a := range g.Assets {
		z, exposure := ZoneOf(a, g.Zones)
		nodes[a.ID.String()] = &Node{
			ID: a.ID.String(), Kind: "asset", Label: a.Hostname, Zone: z, Exposure: exposure,
			Role: a.Role, Criticality: a.Criticality, OS: a.Os,
			Online:    a.SilentSince == nil && now.Sub(a.LastSeen) < 24*time.Hour,
			Listening: len(listenersOf(a)),
		}
	}
	type pair struct{ from, to string }
	edges := map[pair]*Edge{}
	targets := map[pair]map[string]int64{}
	weight := map[string]int64{}
	for _, l := range g.Links {
		src, dst := g.resolve(l.SrcIP, l.SrcAssetID), g.resolve(l.DstIP, nil)
		if src.id == dst.id || (src.asset == nil && dst.asset == nil) {
			continue
		}
		port := l.Proto + "/" + strconv.Itoa(l.DstPort)
		for _, ep := range []endpoint{src, dst} {
			if nodes[ep.id] != nil {
				continue
			}
			if ep.id == "internet" {
				nodes[ep.id] = &Node{ID: ep.id, Kind: "internet", Label: "internet", Zone: Zone{Kind: "external", Source: "auto"}}
				continue
			}
			kind := "discovered"
			if ep.managed {
				kind = "managed"
			}
			nodes[ep.id] = &Node{ID: ep.id, Kind: kind, Label: ep.ip.String(),
				Zone: Classify([]netip.Addr{ep.ip}, nil, nil, g.Zones)}
		}
		if n := nodes[dst.id]; n.Kind == "discovered" || n.Kind == "managed" {
			if !slices.Contains(n.Ports, port) {
				n.Ports = append(n.Ports, port)
			}
		}
		weight[src.id] += l.Count
		weight[dst.id] += l.Count
		k := pair{src.id, dst.id}
		e := edges[k]
		if e == nil {
			e = &Edge{From: src.id, To: dst.id, Note: g.note(src, dst)}
			edges[k] = e
		}
		if !slices.Contains(e.Ports, port) {
			e.Ports = append(e.Ports, port)
		}
		if l.Process != "" && !slices.Contains(e.Processes, l.Process) {
			e.Processes = append(e.Processes, l.Process)
		}
		e.Count += l.Count
		if l.LastSeen.After(e.LastSeen) {
			e.LastSeen = l.LastSeen
		}
		if dst.id == "internet" || src.id == "internet" {
			if targets[k] == nil {
				targets[k] = map[string]int64{}
			}
			other := l.DstIP
			if src.id == "internet" {
				other = l.SrcIP
			}
			targets[k][other+":"+strconv.Itoa(l.DstPort)] += l.Count
		}
	}

	// 未纳管地址太多时按连接量留前 maxDiscovered 个
	var discovered []*Node
	for _, n := range nodes {
		if n.Kind == "discovered" || n.Kind == "managed" {
			discovered = append(discovered, n)
		}
	}
	slices.SortFunc(discovered, func(a, b *Node) int { return cmp.Compare(weight[b.ID], weight[a.ID]) })
	for _, n := range discovered[min(len(discovered), maxDiscovered):] {
		delete(nodes, n.ID)
	}

	out := Graph{Nodes: []Node{}, Edges: []Edge{}}
	for _, n := range nodes {
		slices.Sort(n.Ports)
		out.Nodes = append(out.Nodes, *n)
	}
	for k, e := range edges {
		if nodes[e.From] == nil || nodes[e.To] == nil {
			continue
		}
		slices.Sort(e.Ports)
		slices.Sort(e.Processes)
		e.Targets = top(targets[k], 10)
		out.Edges = append(out.Edges, *e)
	}
	slices.SortFunc(out.Nodes, func(a, b Node) int { return cmp.Compare(a.ID, b.ID) })
	slices.SortFunc(out.Edges, func(a, b Edge) int { return cmp.Or(cmp.Compare(a.From, b.From), cmp.Compare(a.To, b.To)) })
	return out
}

// note AI 给的关系说明，先看发起方对被连方的描述，再看反方向
func (g *Group) note(src, dst endpoint) string {
	if src.asset != nil {
		if n := src.asset.RelationNotes[label(dst)]; n != "" {
			return n
		}
	}
	if dst.asset != nil {
		return dst.asset.RelationNotes[label(src)]
	}
	return ""
}

func top(m map[string]int64, n int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int { return cmp.Or(cmp.Compare(m[b], m[a]), cmp.Compare(a, b)) })
	return keys[:min(len(keys), n)]
}
