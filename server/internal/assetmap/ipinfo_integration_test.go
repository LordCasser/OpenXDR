//go:build integration

package assetmap

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"openxdr/server/ent/ipinfo"
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
