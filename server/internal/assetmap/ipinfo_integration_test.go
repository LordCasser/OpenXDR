//go:build integration

package assetmap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"openxdr/server/ent/intel"
	"openxdr/server/ent/ipinfo"
	"openxdr/server/internal/ipdb"
	"openxdr/server/internal/testdb"
)

// 一轮补信息：只查最近连过的公网地址（跳过内网与已纳管资产），按连接量先后、受每分钟额度约束；
// 撞到 429 本轮停手；查过的进缓存，未到期不重查；图谱与画像带上背景信息与 AI 用途。
func TestEnricherRound(t *testing.T) {
	ctx, client := testdb.New(t)
	group, _ := client.Group.Create().SetName("prod").Save(ctx)
	web, _ := client.Asset.Create().SetHostname("web-01").SetIPAddrs([]string{"10.0.0.1"}).SetGroupID(group.ID).
		SetRelationNotes(map[string]string{"203.0.113.10": "Debian 软件源"}).Save(ctx)
	// 公网地址上的已纳管资产不算外联目的地
	_, _ = client.Asset.Create().SetHostname("edge").SetIPAddrs([]string{"198.51.100.9"}).Save(ctx)

	now := time.Now()
	link := func(dst string, port int, process string, count int64, last time.Time) {
		if err := client.AssetLink.Create().SetSrcIP("10.0.0.1").SetSrcAssetID(web.ID).SetDstIP(dst).SetDstPort(port).SetProto("tcp").
			SetProcess(process).SetCount(count).SetFirstSeen(last).SetLastSeen(last).Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	link("203.0.113.10", 80, "apt", 50, now)
	link("203.0.113.10", 443, "", 5, now)
	link("203.0.113.20", 443, "tailscaled", 30, now)
	link("203.0.113.30", 443, "curl", 10, now)
	link("203.0.113.40", 443, "", 1, now.Add(-10*24*time.Hour)) // 超过一周没再连
	link("10.0.0.2", 5432, "psql", 99, now)
	link("198.51.100.9", 443, "", 99, now)

	var calls atomic.Int32
	quota := atomic.Bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if quota.Load() {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		ip := strings.TrimPrefix(r.URL.Path, "/api/v3/ip_addresses/")
		_, _ = w.Write([]byte(`{"data":{"attributes":{"as_owner":"Owner ` + ip + `","country":"US","last_analysis_stats":{"malicious":0}},
			"relationships":{"resolutions":{"data":[{"id":"` + ip + `mirror.example.org"}]}}}}`))
	}))
	defer srv.Close()
	e := &Enricher{DB: client, VTKey: "k", VTPerMin: 2, VTPerDay: 500, TTL: 7 * 24 * time.Hour, VTBase: srv.URL, HTTP: srv.Client()}

	if err := e.round(ctx, now); err != nil {
		t.Fatal(err)
	}
	rows, _ := client.IPInfo.Query().Order(ipinfo.ByIP()).All(ctx)
	if calls.Load() != 2 || len(rows) != 2 || rows[0].IP != "203.0.113.10" || rows[1].IP != "203.0.113.20" {
		t.Fatalf("每分钟 2 次，应先查连接量最大的两个公网地址: calls=%d %+v", calls.Load(), rows)
	}
	if rows[0].AsOwner != "Owner 203.0.113.10" || len(rows[0].Domains) != 1 || rows[0].Domains[0] != "mirror.example.org" || rows[0].VtAt == nil {
		t.Fatalf("VirusTotal 结果没落库: %+v", rows[0])
	}

	// 下一轮：查过的不再查，剩下的撞到 429，本轮停手不写半截记录
	quota.Store(true)
	if err := e.round(ctx, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatalf("429 后本轮应停手，总调用应为 3，得到 %d", calls.Load())
	}
	if n, _ := client.IPInfo.Query().Count(ctx); n != 3 {
		// 203.0.113.30 已建记录但没有 VT 结果，下轮额度恢复再补
		t.Fatalf("应有 3 条记录，得到 %d", n)
	}
	if r, _ := client.IPInfo.Query().Where(ipinfo.IP("203.0.113.30")).Only(ctx); r.VtAt != nil {
		t.Fatal("429 的地址不该标记为已查")
	}

	// 图谱：公网边按地址合并、带背景信息与本组资产给的用途
	g, err := LoadGroup(ctx, client, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	var targets []PublicDest
	for _, edge := range g.Graph(now).Edges {
		if edge.To == "internet" {
			targets = edge.Targets
		}
	}
	if len(targets) != 4 || targets[0].IP != "203.0.113.10" || targets[0].Count != 55 || len(targets[0].Ports) != 2 ||
		targets[0].Owner != "Owner 203.0.113.10" || targets[0].Purpose != "Debian 软件源" || !targets[0].Checked {
		t.Fatalf("公网边明细不对: %+v", targets)
	}

	// 画像事实：公网地址带背景信息给模型，但不带用途（不回灌模型自己的输出）
	f, err := FactsOf(ctx, client, g.World, web)
	if err != nil {
		t.Fatal(err)
	}
	if f.PublicDestinations != 4 || len(f.Public) != 4 || f.Public[0].Owner == "" || f.Public[0].Purpose != "" {
		t.Fatalf("画像公网事实不对: %d %+v", f.PublicDestinations, f.Public)
	}
}

// 只有离线库（不开反向解析、不配 VirusTotal）也补：公网地址（含 IPv6）都写上 ipdb_* 字段，库里没有的记成查过；
// 私网不查不落库；之后 VirusTotal 补的写自己的字段，不覆盖离线库的；图谱归属 VirusTotal 优先、离线库补缺
func TestEnricherIPDB(t *testing.T) {
	ctx, client := testdb.New(t)
	group := client.Group.Create().SetName("prod").SaveX(ctx)
	web := client.Asset.Create().SetHostname("web-01").SetIPAddrs([]string{"10.0.0.1"}).SetGroupID(group.ID).SaveX(ctx)
	now := time.Now()
	for i, dst := range []string{"203.0.113.10", "2001:db8:1::5", "203.0.113.200", "10.0.0.2"} {
		client.AssetLink.Create().SetSrcIP("10.0.0.1").SetSrcAssetID(web.ID).SetDstIP(dst).SetDstPort(443).SetProto("tcp").
			SetCount(int64(10 - i)).SetFirstSeen(now).SetLastSeen(now).ExecX(ctx)
	}
	db := &ipdb.DB{Dir: "../ipdb/testdata"}
	defer db.Close()
	e := &Enricher{DB: client, IPDB: db, VTPerMin: 4, VTPerDay: 500, TTL: 7 * 24 * time.Hour}
	if err := e.round(ctx, now); err != nil {
		t.Fatal(err)
	}
	rows := client.IPInfo.Query().Order(ipinfo.ByIP()).AllX(ctx)
	if len(rows) != 3 {
		t.Fatalf("三个公网地址应落库，私网不查: %+v", rows)
	}
	got, firstAt := map[string]string{}, map[string]time.Time{}
	for _, r := range rows {
		if r.IpdbAt == nil || r.VtAt != nil || r.PtrAt != nil {
			t.Fatalf("只该有离线库结果: %+v", r)
		}
		got[r.IP], firstAt[r.IP] = fmt.Sprintf("%d|%s|%s", r.IpdbAsn, r.IpdbOrg, r.IpdbCountry), *r.IpdbAt
	}
	want := map[string]string{"203.0.113.10": "64500|Example Net A|AU", "2001:db8:1::5": "64502|Example Net V6|JP", "203.0.113.200": "0||AU"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("离线库结果不对: %v", got)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"attributes":{"as_owner":"VT Owner","asn":64999,"country":"NL"}}}`))
	}))
	defer srv.Close()
	e.VTKey, e.VTBase, e.HTTP, e.VTPerMin = "k", srv.URL, srv.Client(), 1
	if err := e.round(ctx, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	r := client.IPInfo.Query().Where(ipinfo.IP("203.0.113.10")).OnlyX(ctx)
	if r.AsOwner != "VT Owner" || r.Asn != 64999 || r.IpdbOrg != "Example Net A" || r.IpdbAsn != 64500 || !r.IpdbAt.Equal(firstAt[r.IP]) {
		t.Fatalf("VirusTotal 不该覆盖离线库字段，离线库未到期不重查: %+v", r)
	}

	g, err := LoadGroup(ctx, client, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	var targets []PublicDest
	for _, edge := range g.Graph(now).Edges {
		if edge.To == "internet" {
			targets = edge.Targets
		}
	}
	byIP := map[string]PublicDest{}
	for _, d := range targets {
		byIP[d.IP] = d
	}
	if d := byIP["203.0.113.10"]; d.Owner != "VT Owner" || d.ASN != 64999 || d.Country != "NL" || d.IPDB {
		t.Fatalf("VirusTotal 有的归属用它的: %+v", d)
	}
	if d := byIP["2001:db8:1::5"]; d.Owner != "Example Net V6" || d.ASN != 64502 || d.Country != "JP" || !d.IPDB {
		t.Fatalf("没有 VirusTotal 的用离线库并标出: %+v", d)
	}
}

// VirusTotal 判恶意达到阈值的地址进威胁情报（之后连它就出告警）；重查不再达到阈值的立即失效；
// 人工录入的同一地址不被改写
func TestEnricherFlagsIntel(t *testing.T) {
	ctx, client := testdb.New(t)
	web, _ := client.Asset.Create().SetHostname("web-01").SetIPAddrs([]string{"10.0.0.1"}).Save(ctx)
	now := time.Now()
	for _, ip := range []string{"203.0.113.66", "203.0.113.77"} {
		if err := client.AssetLink.Create().SetSrcIP("10.0.0.1").SetSrcAssetID(web.ID).SetDstIP(ip).SetDstPort(4444).SetProto("tcp").
			SetCount(5).SetFirstSeen(now).SetLastSeen(now).Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// 人工已录入 .77：不论 VirusTotal 怎么说都不动
	_ = client.Intel.Create().SetKind(intel.KindIP).SetValue("203.0.113.77").SetSource("manual").SetNote("人工").Exec(ctx)
	malicious := atomic.Int32{}
	malicious.Store(4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"data":{"attributes":{"as_owner":"Bad Hosting","last_analysis_stats":{"malicious":%d}}}}`, malicious.Load())
	}))
	defer srv.Close()
	e := &Enricher{DB: client, VTPerMin: 4, VTPerDay: 500, TTL: 7 * 24 * time.Hour, VTBase: srv.URL, HTTP: srv.Client(),
		Settings: func() (bool, string, int) { return false, "k", 3 }}
	if err := e.round(ctx, now); err != nil {
		t.Fatal(err)
	}
	row, err := client.Intel.Query().Where(intel.ValueEQ("203.0.113.66")).Only(ctx)
	if err != nil || row.Source != "virustotal" || row.ExpiresAt == nil || !row.ExpiresAt.After(now.Add(7*24*time.Hour)) || !strings.Contains(*row.Note, "4 个引擎") {
		t.Fatalf("达到阈值应加入情报: %+v %v", row, err)
	}
	if m, _ := client.Intel.Query().Where(intel.ValueEQ("203.0.113.77")).Only(ctx); m.Source != "manual" || *m.Note != "人工" {
		t.Fatalf("人工情报不应被改写: %+v", m)
	}

	// 一周后重查，VirusTotal 改判：立即失效
	malicious.Store(1)
	later := now.Add(8 * 24 * time.Hour)
	if err := e.round(ctx, later); err != nil {
		t.Fatal(err)
	}
	if row, _ = client.Intel.Query().Where(intel.ValueEQ("203.0.113.66")).Only(ctx); row.ExpiresAt == nil || row.ExpiresAt.After(later) {
		t.Fatalf("不再达到阈值应立即失效: %+v", row.ExpiresAt)
	}
}

// 告警里出现的公网地址先补：情报命中与入站对端不在依赖边里，以前永远轮不到；
// 反向解析临时失败不落「查过」，隔一阵重试，不拖住别的地址
func TestEnricherAlertPeers(t *testing.T) {
	ctx, client := testdb.New(t)
	group := client.Group.Create().SetName("prod").SaveX(ctx)
	gw := client.Asset.Create().SetHostname("gateway").SetIPAddrs([]string{"10.1.1.100"}).SetGroupID(group.ID).SaveX(ctx)
	now := time.Now()
	client.AssetLink.Create().SetSrcIP("10.1.1.100").SetSrcAssetID(gw.ID).SetDstIP("203.0.113.10").SetDstPort(443).SetProto("tcp").
		SetCount(500).SetFirstSeen(now).SetLastSeen(now).ExecX(ctx)
	inbound := client.Event.Create().SetTs(now).SetClassUID(4001).SetSource("agent").SetAssetID(gw.ID).
		SetRaw(json.RawMessage(`{"src_endpoint":{"ip":"176.120.22.61","port":58364},"dst_endpoint":{"ip":"10.1.1.100","port":443},"connection_info":{"direction":"inbound"}}`)).SaveX(ctx)
	client.Alert.Create().SetTs(now).SetRuleID("intel:ip:176.120.22.61").SetSeverity(3).SetAssetID(gw.ID).SetEventID(inbound.ID).ExecX(ctx)
	login := client.Event.Create().SetTs(now).SetClassUID(3002).SetSource("agent").SetAssetID(gw.ID).
		SetRaw(json.RawMessage(`{"src_endpoint":{"ip":"198.51.100.44"}}`)).SaveX(ctx)
	client.Alert.Create().SetTs(now.Add(-time.Minute)).SetRuleID("ssh-brute").SetSeverity(3).SetAssetID(gw.ID).SetEventID(login.ID).ExecX(ctx)

	var vtCalls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vtCalls = append(vtCalls, strings.TrimPrefix(r.URL.Path, "/api/v3/ip_addresses/"))
		_, _ = w.Write([]byte(`{"data":{"attributes":{"as_owner":"Some ISP","country":"RU"}}}`))
	}))
	defer srv.Close()
	var dials atomic.Int32
	e := &Enricher{DB: client, PTR: true, VTKey: "k", VTPerMin: 2, VTPerDay: 500, TTL: 7 * 24 * time.Hour,
		VTBase: srv.URL, HTTP: srv.Client(), Resolver: &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("DNS 不可达")
		}}}
	if err := e.round(ctx, now); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(vtCalls, []string{"176.120.22.61", "198.51.100.44"}) {
		t.Fatalf("应先查告警里的地址（最近的在前），再轮到外联：%v", vtCalls)
	}
	row := client.IPInfo.Query().Where(ipinfo.IP("176.120.22.61")).OnlyX(ctx)
	if row.AsOwner != "Some ISP" || row.VtAt == nil || row.PtrAt != nil {
		t.Fatalf("情报命中的入站对端应补上 VirusTotal，反向解析失败不该记成查过: %+v", row)
	}
	if dials.Load() == 0 {
		t.Fatal("应尝试过反向解析")
	}

	// 解析失败的地址退避期内不再试，到点重试
	before := dials.Load()
	if err := e.round(ctx, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if dials.Load() != before {
		t.Fatalf("退避期内不该重试失败的地址: %d → %d", before, dials.Load())
	}
	if err := e.round(ctx, now.Add(ptrRetryAfter+time.Minute)); err != nil {
		t.Fatal(err)
	}
	if dials.Load() == before {
		t.Fatal("退避期过后应重试")
	}
}
