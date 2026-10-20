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

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/assetlink"
	"openxdr/server/ent/event"
	"openxdr/server/ent/intel"
	"openxdr/server/ent/ipinfo"
	"openxdr/server/internal/ipdb"
)

const (
	// 只给最近一周还在连的公网地址补信息，陈年地址不浪费额度
	enrichWindow = 7 * 24 * time.Hour
	// 每轮离线库查询的上限：本地查很快，限的是逐条写库
	ipdbPerRound = 1000
	// 每轮反向解析的上限：解析是串行的，单个最多等 ptrTimeout
	ptrPerRound = 20
	ptrTimeout  = 3 * time.Second
	// 反向解析临时失败（超时、DNS 服务出错）的地址隔多久再试；查无记录不算失败
	ptrRetryAfter = 30 * time.Minute
	maxDomains    = 5
)

var (
	errVTQuota = errors.New("VirusTotal 额度用尽")
	errVTAuth  = errors.New("VirusTotal 拒绝了 API key")
)

// Enricher 给公网目的地址补背景信息，供人和 AI 认地址：离线库（AS / 国家，本地查、不外发地址）、
// 反向解析（PTR），配置了 VT_API_KEY 再查 VirusTotal。
// 按最近一周的连接量从多到少查，结果缓存 TTL 后重查。VirusTotal 免费额度很紧（4 次/分钟、500 次/天），
// 按分钟与天两道限额走；撞到 429 停到下一轮，key 被拒停一小时，都不影响图谱与标注本身。
type Enricher struct {
	DB *ent.Client
	// Settings 每轮取一次反向解析开关、VirusTotal key 与转情报阈值（控制台可改）；为空用下面的固定值
	Settings   func() (ptr bool, vtKey string, alertMin int)
	PTR        bool
	VTKey      string
	VTAlertMin int
	VTPerMin   int
	VTPerDay   int
	TTL        time.Duration
	Interval   time.Duration
	HTTP       *http.Client
	// 测试替换；空为官方地址
	VTBase   string
	Resolver *net.Resolver
	// 离线 IP 归属库；为空或库缺失时不填 ipdb_* 字段
	IPDB *ipdb.DB

	day       string
	usedToday int
	pauseTill time.Time
	// 反向解析临时失败的地址到什么时候再试：只在内存里，换节点或重启从头来
	ptrRetry map[string]time.Time
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

// round 一轮：挑出到期的地址，离线库、反向解析与 VirusTotal 各按自己的额度查，查到多少写多少
func (e *Enricher) round(ctx context.Context, now time.Time) error {
	if e.Settings != nil {
		e.PTR, e.VTKey, e.VTAlertMin = e.Settings()
	}
	e.IPDB.Refresh()
	if !e.PTR && e.VTKey == "" && !e.IPDB.Ready() {
		return nil
	}
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
	ptrLeft, vtLeft, geoLeft := 0, e.vtBudget(now), 0
	if e.PTR {
		ptrLeft = ptrPerRound
	}
	if e.IPDB.Ready() {
		geoLeft = ipdbPerRound
	}
	for _, ip := range ips {
		if ptrLeft == 0 && vtLeft == 0 && geoLeft == 0 {
			break
		}
		info := known[ip]
		doGeo := geoLeft > 0 && (info == nil || stale(info.IpdbAt))
		doPTR := ptrLeft > 0 && (info == nil || stale(info.PtrAt)) && !now.Before(e.ptrRetry[ip])
		doVT := vtLeft > 0 && (info == nil || stale(info.VtAt))
		if !doGeo && !doPTR && !doVT {
			continue
		}
		upd := ipUpdate{}
		if doGeo {
			geoLeft--
			g := e.geoOf(ip)
			upd.geo = &g
		}
		if doPTR {
			ptrLeft--
			// 临时失败不落库，过一阵再试；不然记成「查过、没有」要等缓存到期才重查
			if name, err := e.lookupPTR(ctx, ip); err != nil {
				if e.ptrRetry == nil {
					e.ptrRetry = map[string]time.Time{}
				}
				e.ptrRetry[ip] = now.Add(ptrRetryAfter)
				slog.Debug("反向解析失败，稍后重试", "ip", ip, "err", err)
			} else {
				delete(e.ptrRetry, ip)
				upd.ptr = &name
			}
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
		if upd.vt != nil {
			if err := e.syncIntel(ctx, ip, *upd.vt, now); err != nil {
				return err
			}
		}
	}
	return nil
}

type ipSum struct {
	DstIP string `json:"dst_ip"`
	Sum   int64  `json:"sum"`
}

// candidates 待补信息的公网地址（不含已纳管资产的地址）：先是最近一周告警里出现的对端，最近的在前——
// 情报命中与入站对端不在依赖边里，只按外联挑永远轮不到；再是最近一周连过的地址，按连接量从多到少
func (e *Enricher) candidates(ctx context.Context, now time.Time) ([]string, error) {
	peers, err := e.alertPeers(ctx, now)
	if err != nil {
		return nil, err
	}
	var sums []ipSum
	err = e.DB.AssetLink.Query().Where(assetlink.LastSeenGT(now.Add(-enrichWindow))).
		GroupBy(assetlink.FieldDstIP).Aggregate(ent.Sum(assetlink.FieldCount)).Scan(ctx, &sums)
	if err != nil {
		return nil, err
	}
	w, err := LoadWorld(ctx, e.DB)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(sums, func(a, b ipSum) int { return cmp.Or(cmp.Compare(b.Sum, a.Sum), cmp.Compare(a.DstIP, b.DstIP)) })
	for _, s := range sums {
		peers = append(peers, s.DstIP)
	}
	var out []string
	seen := map[string]bool{}
	for _, ip := range peers {
		if addr, err := netip.ParseAddr(ip); err == nil && Public(addr) && w.ByIP[addr] == nil && !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out, nil
}

// alertPeers 最近一周告警里出现的地址，最近的在前：情报命中的地址取自规则 ID，其余取告警对应事件的两端。
// 平台自己下发的指令触发的告警不算；只取最近 alertPeerLimit 条告警，公网与否由调用方筛
func (e *Enricher) alertPeers(ctx context.Context, now time.Time) ([]string, error) {
	since := now.Add(-enrichWindow)
	alerts, err := e.DB.Alert.Query().Where(alert.TsGT(since), alert.CommandIDIsNil()).
		Order(ent.Desc(alert.FieldTs)).Limit(alertPeerLimit).All(ctx)
	if err != nil {
		return nil, err
	}
	var ids []uuid.UUID
	for _, a := range alerts {
		if a.EventID != nil {
			ids = append(ids, *a.EventID)
		}
	}
	raws := map[uuid.UUID][]string{}
	if len(ids) > 0 {
		// 事件按天分区：带上时间下限，只扫窗口内的分区
		events, err := e.DB.Event.Query().Where(event.IDIn(ids...), event.TsGT(since.Add(-24*time.Hour))).
			Select(event.FieldRaw).All(ctx)
		if err != nil {
			return nil, err
		}
		for _, ev := range events {
			raws[ev.ID] = endpointIPs(ev.Raw)
		}
	}
	var out []string
	for _, a := range alerts {
		if ip, ok := strings.CutPrefix(a.RuleID, "intel:ip:"); ok {
			out = append(out, ip)
		}
		if a.EventID != nil {
			out = append(out, raws[*a.EventID]...)
		}
	}
	return out, nil
}

// alertPeerLimit 每轮最多看多少条告警找对端：生产一周几百条，够用且不拖慢一轮
const alertPeerLimit = 2000

// endpointIPs 事件两端的地址；外部数据不可信，解析不了就当没有
func endpointIPs(raw json.RawMessage) []string {
	var ev struct {
		Src struct {
			IP string `json:"ip"`
		} `json:"src_endpoint"`
		Dst struct {
			IP string `json:"ip"`
		} `json:"dst_endpoint"`
	}
	if json.Unmarshal(raw, &ev) != nil {
		return nil
	}
	var out []string
	for _, ip := range []string{ev.Src.IP, ev.Dst.IP} {
		if ip != "" {
			out = append(out, ip)
		}
	}
	return out
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

// lookupPTR 查无记录返回空串；超时、DNS 服务出错这类临时失败返回错误，由调用方稍后重试
func (e *Enricher) lookupPTR(ctx context.Context, ip string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, ptrTimeout)
	defer cancel()
	r := cmp.Or(e.Resolver, net.DefaultResolver)
	names, err := r.LookupAddr(ctx, ip)
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		return "", nil
	case err != nil:
		return "", err
	case len(names) == 0:
		return "", nil
	}
	return clean(strings.TrimSuffix(names[0], "."), 253), nil
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

// syncIntel 达到阈值的地址加进威胁情报，之后再有主机连它就按情报命中出告警；到期跟着缓存期走。
// 重查后不再达到阈值的立即失效。人工或别的来源已有的同一地址不动
func (e *Enricher) syncIntel(ctx context.Context, ip string, v vtResult, now time.Time) error {
	hit := e.VTAlertMin > 0 && v.malicious >= e.VTAlertMin
	row, err := e.DB.Intel.Query().Where(intel.KindEQ(intel.KindIP), intel.ValueEQ(ip)).Only(ctx)
	switch {
	case ent.IsNotFound(err):
		if !hit {
			return nil
		}
		note := fmt.Sprintf("VirusTotal %d 个引擎判恶意 · %s", v.malicious, cmp.Or(v.owner, "-"))
		err = e.DB.Intel.Create().SetKind(intel.KindIP).SetValue(ip).SetSource(intelSource).SetSeverity(4).
			SetNote(note).SetExpiresAt(now.Add(e.TTL + 24*time.Hour)).Exec(ctx)
		if ent.IsConstraintError(err) {
			return nil
		}
		return err
	case err != nil:
		return err
	case row.Source != intelSource:
		return nil
	case hit:
		return row.Update().SetNote(fmt.Sprintf("VirusTotal %d 个引擎判恶意 · %s", v.malicious, cmp.Or(v.owner, "-"))).
			SetExpiresAt(now.Add(e.TTL + 24*time.Hour)).Exec(ctx)
	default:
		return row.Update().SetExpiresAt(now).Exec(ctx)
	}
}

const intelSource = "virustotal"

// geoOf 离线库里查一个地址；只查公网地址，私网与保留地址一律空。库数据也截断清洗
func (e *Enricher) geoOf(ip string) ipdb.Info {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !Public(addr) {
		return ipdb.Info{}
	}
	g := e.IPDB.Lookup(addr)
	return ipdb.Info{ASN: g.ASN, Org: clean(g.Org, 120), Country: clean(g.Country, 8)}
}

type ipUpdate struct {
	ptr *string
	vt  *vtResult
	geo *ipdb.Info
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
		if g := u.geo; g != nil {
			c.SetIpdbAsn(g.ASN).SetIpdbOrg(g.Org).SetIpdbCountry(g.Country).SetIpdbAt(now)
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
	if g := u.geo; g != nil {
		upd.SetIpdbAsn(g.ASN).SetIpdbOrg(g.Org).SetIpdbCountry(g.Country).SetIpdbAt(now)
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
	ASN        int       `json:"asn,omitempty"`
	Country    string    `json:"country,omitempty"`
	Malicious  int       `json:"malicious,omitempty"`
	Suspicious int       `json:"suspicious,omitempty"`
	Domains    []string  `json:"domains,omitempty"`
	// VirusTotal 查过（哪怕没有记录）
	Checked bool `json:"checked,omitempty"`
	// 展示的归属里有离线库（DB-IP）的数据：控制台据此署名，CC BY 4.0 的要求
	IPDB bool `json:"ipdb,omitempty"`
	// AI 标注给的用途，只在接口里填，不回灌给模型
	Purpose string `json:"purpose,omitempty"`
	// 上机调查或人工给的结论，优先于 Purpose
	Note *ServiceNote `json:"note,omitempty"`
}

// WithNotes 填上资产给这些地址的用途与调查结论（只在接口里，不进模型上下文）
func WithNotes(ds []PublicDest, a *ent.Asset) []PublicDest {
	if a == nil {
		return ds
	}
	notes := EgressNotesOf(a)
	for i := range ds {
		ds[i].Purpose = a.RelationNotes[ds[i].IP]
		if n, ok := notes[ds[i].IP]; ok {
			ds[i].Note = &n
		}
	}
	return ds
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
			d.PTR, d.Malicious, d.Suspicious, d.Domains, d.Checked = i.Ptr, i.Malicious, i.Suspicious, i.Domains, i.VtAt != nil
			// 归属：VirusTotal 有的用它的，没有的用离线库补
			d.Owner, d.ASN, d.Country = cmp.Or(i.AsOwner, i.IpdbOrg), cmp.Or(i.Asn, i.IpdbAsn), cmp.Or(i.Country, i.IpdbCountry)
			d.IPDB = d.Owner != i.AsOwner || d.ASN != i.Asn || d.Country != i.Country
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
