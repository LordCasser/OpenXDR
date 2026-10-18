package assetmap

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/assetlink"
	"openxdr/server/ent/ipinfo"
)

const (
	// 只给最近一周还在连的公网地址补信息，陈年地址不浪费额度
	enrichWindow = 7 * 24 * time.Hour
	// 每轮反向解析的上限：解析是串行的，单个最多等 ptrTimeout
	ptrPerRound = 20
	ptrTimeout  = 3 * time.Second
	maxDomains  = 5
)

var (
	errVTQuota = errors.New("VirusTotal 额度用尽")
	errVTAuth  = errors.New("VirusTotal 拒绝了 API key")
)

// Enricher 给公网目的地址补背景信息，供人和 AI 认地址：反向解析（PTR），配置了 VT_API_KEY 再查 VirusTotal。
// 按最近一周的连接量从多到少查，结果缓存 TTL 后重查。VirusTotal 免费额度很紧（4 次/分钟、500 次/天），
// 按分钟与天两道限额走；撞到 429 停到下一轮，key 被拒停一小时，都不影响图谱与标注本身。
type Enricher struct {
	DB       *ent.Client
	PTR      bool
	VTKey    string
	VTPerMin int
	VTPerDay int
	TTL      time.Duration
	Interval time.Duration
	HTTP     *http.Client
	// 测试替换；空为官方地址
	VTBase   string
	Resolver *net.Resolver

	day       string
	usedToday int
	pauseTill time.Time
}

func (e *Enricher) Run(ctx context.Context) {
	ticker := time.NewTicker(e.Interval)
	defer ticker.Stop()
	for {
		if err := e.round(ctx, time.Now()); err != nil && ctx.Err() == nil {
			slog.Warn("公网地址信息查询中断", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// round 一轮：挑出到期的地址，反向解析与 VirusTotal 各按自己的额度查，查到多少写多少
func (e *Enricher) round(ctx context.Context, now time.Time) error {
	ips, err := e.candidates(ctx, now)
	if err != nil || len(ips) == 0 {
		return err
	}
	rows, err := e.DB.IPInfo.Query().Where(ipinfo.IPIn(ips...)).All(ctx)
	if err != nil {
		return err
	}
	known := map[string]*ent.IPInfo{}
	for _, r := range rows {
		known[r.IP] = r
	}
	stale := func(at *time.Time) bool { return at == nil || now.Sub(*at) > e.TTL }
	ptrLeft, vtLeft := 0, e.vtBudget(now)
	if e.PTR {
		ptrLeft = ptrPerRound
	}
	for _, ip := range ips {
		if ptrLeft == 0 && vtLeft == 0 {
			break
		}
		info := known[ip]
		doPTR := ptrLeft > 0 && (info == nil || stale(info.PtrAt))
		doVT := vtLeft > 0 && (info == nil || stale(info.VtAt))
		if !doPTR && !doVT {
			continue
		}
		upd := ipUpdate{}
		if doPTR {
			ptrLeft--
			name := e.lookupPTR(ctx, ip)
			upd.ptr = &name
		}
		if doVT {
			vtLeft--
			e.usedToday++
			vt, err := e.lookupVT(ctx, ip)
			switch {
			case errors.Is(err, errVTQuota):
				// 额度以 VirusTotal 说的为准：本轮停手，下一轮再看
				vtLeft = 0
			case errors.Is(err, errVTAuth):
				e.pauseTill = now.Add(time.Hour)
				vtLeft = 0
				slog.Warn("VirusTotal 拒绝了 API key，一小时后再试")
			case err != nil:
				slog.Warn("VirusTotal 查询失败", "ip", ip, "err", err)
			default:
				upd.vt = &vt
			}
		}
		if err := e.save(ctx, ip, info, upd, now); err != nil {
			return err
		}
	}
	return nil
}

type ipSum struct {
	DstIP string `json:"dst_ip"`
	Sum   int64  `json:"sum"`
}

// candidates 最近一周连过的公网地址（不含已纳管资产的地址），按连接量从多到少
func (e *Enricher) candidates(ctx context.Context, now time.Time) ([]string, error) {
	var sums []ipSum
	err := e.DB.AssetLink.Query().Where(assetlink.LastSeenGT(now.Add(-enrichWindow))).
		GroupBy(assetlink.FieldDstIP).Aggregate(ent.Sum(assetlink.FieldCount)).Scan(ctx, &sums)
	if err != nil {
		return nil, err
	}
	w, err := LoadWorld(ctx, e.DB)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(sums, func(a, b ipSum) int { return cmp.Or(cmp.Compare(b.Sum, a.Sum), cmp.Compare(a.DstIP, b.DstIP)) })
	var out []string
	for _, s := range sums {
		if addr, err := netip.ParseAddr(s.DstIP); err == nil && Public(addr) && w.ByIP[addr] == nil {
			out = append(out, s.DstIP)
		}
	}
	return out, nil
}

// vtBudget 本轮还能查几次：每分钟上限，再受当天剩余额度与暂停期约束
func (e *Enricher) vtBudget(now time.Time) int {
	if e.VTKey == "" || now.Before(e.pauseTill) {
		return 0
	}
	if day := now.UTC().Format(time.DateOnly); day != e.day {
		e.day, e.usedToday = day, 0
	}
	return max(0, min(e.VTPerMin, e.VTPerDay-e.usedToday))
}

func (e *Enricher) lookupPTR(ctx context.Context, ip string) string {
	ctx, cancel := context.WithTimeout(ctx, ptrTimeout)
	defer cancel()
	r := cmp.Or(e.Resolver, net.DefaultResolver)
	names, err := r.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return clean(strings.TrimSuffix(names[0], "."), 253)
}

type vtResult struct {
	owner      string
	asn        int
	country    string
	malicious  int
	suspicious int
	domains    []string
}

// lookupVT 查一个地址；404 表示 VirusTotal 没有它的记录，按查过但没有信息处理
func (e *Enricher) lookupVT(ctx context.Context, ip string) (vtResult, error) {
	base := cmp.Or(e.VTBase, "https://www.virustotal.com")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v3/ip_addresses/"+url.PathEscape(ip)+"?relationships=resolutions", nil)
	if err != nil {
		return vtResult{}, err
	}
	req.Header.Set("x-apikey", e.VTKey)
	resp, err := e.HTTP.Do(req)
	if err != nil {
		return vtResult{}, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return vtResult{}, nil
	case http.StatusTooManyRequests:
		return vtResult{}, errVTQuota
	case http.StatusUnauthorized, http.StatusForbidden:
		return vtResult{}, errVTAuth
	default:
		return vtResult{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return parseVT(resp.Body, ip)
}

// parseVT 外部返回不可信：只取用得上的字段并截断
func parseVT(body io.Reader, ip string) (vtResult, error) {
	var raw struct {
		Data struct {
			Attributes struct {
				ASOwner string `json:"as_owner"`
				ASN     int    `json:"asn"`
				Country string `json:"country"`
				Stats   struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
			Relationships struct {
				Resolutions struct {
					Data []struct {
						ID string `json:"id"`
					} `json:"data"`
				} `json:"resolutions"`
			} `json:"relationships"`
		} `json:"data"`
	}
	if err := json.NewDecoder(body).Decode(&raw); err != nil {
		return vtResult{}, fmt.Errorf("返回不是合法 JSON: %w", err)
	}
	a := raw.Data.Attributes
	r := vtResult{owner: clean(a.ASOwner, 120), asn: a.ASN, country: clean(a.Country, 8), malicious: a.Stats.Malicious, suspicious: a.Stats.Suspicious}
	// 解析记录的 id 是「地址+域名」拼在一起
	for _, d := range raw.Data.Relationships.Resolutions.Data {
		if host := clean(strings.TrimPrefix(d.ID, ip), 253); host != "" && host != d.ID && !slices.Contains(r.domains, host) && len(r.domains) < maxDomains {
			r.domains = append(r.domains, host)
		}
	}
	return r, nil
}

type ipUpdate struct {
	ptr *string
	vt  *vtResult
}

func (e *Enricher) save(ctx context.Context, ip string, info *ent.IPInfo, u ipUpdate, now time.Time) error {
	if info == nil {
		c := e.DB.IPInfo.Create().SetIP(ip)
		if u.ptr != nil {
			c.SetPtr(*u.ptr).SetPtrAt(now)
		}
		if v := u.vt; v != nil {
			c.SetAsOwner(v.owner).SetAsn(v.asn).SetCountry(v.country).SetMalicious(v.malicious).SetSuspicious(v.suspicious).SetDomains(v.domains).SetVtAt(now)
		}
		// 别的节点抢先写了同一个地址：下一轮按已有记录更新即可
		if err := c.Exec(ctx); err != nil && !ent.IsConstraintError(err) {
			return err
		}
		return nil
	}
	upd := info.Update()
	if u.ptr != nil {
		upd.SetPtr(*u.ptr).SetPtrAt(now)
	}
	if v := u.vt; v != nil {
		upd.SetAsOwner(v.owner).SetAsn(v.asn).SetCountry(v.country).SetMalicious(v.malicious).SetSuspicious(v.suspicious).SetDomains(v.domains).SetVtAt(now)
	}
	return upd.Exec(ctx)
}

// PublicDest 一个公网目的地址：连它的端口、进程、连接量，加上缓存里的背景信息与 AI 给的用途
type PublicDest struct {
	IP         string    `json:"ip"`
	Ports      []string  `json:"ports"`
	Processes  []string  `json:"processes,omitempty"`
	Count      int64     `json:"count"`
	LastSeen   time.Time `json:"lastSeen"`
	PTR        string    `json:"ptr,omitempty"`
	Owner      string    `json:"owner,omitempty"`
	Country    string    `json:"country,omitempty"`
	Malicious  int       `json:"malicious,omitempty"`
	Suspicious int       `json:"suspicious,omitempty"`
	Domains    []string  `json:"domains,omitempty"`
	// VirusTotal 查过（哪怕没有记录）
	Checked bool `json:"checked,omitempty"`
	// AI 标注给的用途，只在接口里填，不回灌给模型
	Purpose string `json:"purpose,omitempty"`
}

// hit 一条连到公网地址的依赖边，ip 是公网那一端
type hit struct {
	ip, port, process string
	count             int64
	last              time.Time
}

func hitOf(l *ent.AssetLink, ip string) hit {
	return hit{ip: ip, port: l.Proto + "/" + strconv.Itoa(l.DstPort), process: l.Process, count: l.Count, last: l.LastSeen}
}

// publicDests 按地址合并，端口与进程去重，连接量从多到少取前 n 个
func publicDests(hits []hit, info map[string]*ent.IPInfo, n int) []PublicDest {
	by := map[string]*PublicDest{}
	for _, h := range hits {
		d := by[h.ip]
		if d == nil {
			d = &PublicDest{IP: h.ip}
			by[h.ip] = d
		}
		if !slices.Contains(d.Ports, h.port) {
			d.Ports = append(d.Ports, h.port)
		}
		if h.process != "" && !slices.Contains(d.Processes, h.process) {
			d.Processes = append(d.Processes, h.process)
		}
		d.Count += h.count
		if h.last.After(d.LastSeen) {
			d.LastSeen = h.last
		}
	}
	out := make([]PublicDest, 0, len(by))
	for _, d := range by {
		slices.Sort(d.Ports)
		slices.Sort(d.Processes)
		if i := info[d.IP]; i != nil {
			d.PTR, d.Owner, d.Country, d.Malicious, d.Suspicious, d.Domains, d.Checked = i.Ptr, i.AsOwner, i.Country, i.Malicious, i.Suspicious, i.Domains, i.VtAt != nil
		}
		out = append(out, *d)
	}
	slices.SortFunc(out, func(a, b PublicDest) int { return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.IP, b.IP)) })
	return out[:min(len(out), n)]
}

// loadInfo 取一批地址的缓存信息
func loadInfo(ctx context.Context, db *ent.Client, ips []string) (map[string]*ent.IPInfo, error) {
	out := map[string]*ent.IPInfo{}
	if len(ips) == 0 {
		return out, nil
	}
	rows, err := db.IPInfo.Query().Where(ipinfo.IPIn(ips...)).All(ctx)
	for _, r := range rows {
		out[r.IP] = r
	}
	return out, err
}
