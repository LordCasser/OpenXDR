package assetmap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/ent"
)

func TestPublicDests(t *testing.T) {
	now := time.Now()
	hits := []hit{
		{ip: "1.1.1.1", port: "tcp/443", process: "curl", count: 5, last: now.Add(-time.Hour)},
		{ip: "1.1.1.1", port: "tcp/80", process: "", count: 2, last: now},
		{ip: "1.1.1.1", port: "tcp/443", process: "curl", count: 1, last: now.Add(-2 * time.Hour)},
		{ip: "8.8.8.8", port: "udp/53", process: "systemd-resolve", count: 50, last: now},
		{ip: "9.9.9.9", port: "udp/53", count: 1, last: now},
	}
	vt := now
	info := map[string]*ent.IPInfo{"1.1.1.1": {IP: "1.1.1.1", Ptr: "one.one.one.one", AsOwner: "CLOUDFLARENET", Malicious: 1, VtAt: &vt}}
	got := publicDests(hits, info, 2)
	if len(got) != 2 || got[0].IP != "8.8.8.8" || got[1].IP != "1.1.1.1" {
		t.Fatalf("应按连接量取前 2 个: %+v", got)
	}
	d := got[1]
	if d.Count != 8 || !d.LastSeen.Equal(now) || strings.Join(d.Ports, ",") != "tcp/443,tcp/80" || strings.Join(d.Processes, ",") != "curl" {
		t.Fatalf("同一地址应合并端口、进程与连接量: %+v", d)
	}
	if d.PTR != "one.one.one.one" || d.Owner != "CLOUDFLARENET" || d.Malicious != 1 || !d.Checked || got[0].Checked {
		t.Fatalf("背景信息没带上: %+v", got)
	}
}

func TestParseVT(t *testing.T) {
	body := `{"data":{"attributes":{"as_owner":"Tailscale Inc","asn":41641,"country":"US","last_analysis_stats":{"malicious":0,"suspicious":1}},
		"relationships":{"resolutions":{"data":[{"id":"1.2.3.4derp1.tailscale.com"},{"id":"1.2.3.4derp1.tailscale.com"},{"id":"1.2.3.4"}]}}}}`
	r, err := parseVT(strings.NewReader(body), "1.2.3.4")
	if err != nil || r.owner != "Tailscale Inc" || r.asn != 41641 || r.country != "US" || r.suspicious != 1 || strings.Join(r.domains, ",") != "derp1.tailscale.com" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := parseVT(strings.NewReader("<html>"), "1.2.3.4"); err == nil {
		t.Fatal("非 JSON 应报错")
	}
}

func TestLookupVTStatus(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "k" || r.URL.Path != "/api/v3/ip_addresses/1.2.3.4" || r.URL.Query().Get("relationships") != "resolutions" {
			t.Errorf("请求不对: %s %v", r.URL, r.Header)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"data":{"attributes":{"as_owner":"X"}}}`))
	}))
	defer srv.Close()
	e := &Enricher{VTKey: "k", VTBase: srv.URL, HTTP: srv.Client()}
	if r, err := e.lookupVT(context.Background(), "1.2.3.4"); err != nil || r.owner != "X" {
		t.Fatalf("%+v %v", r, err)
	}
	for code, want := range map[int]error{http.StatusTooManyRequests: errVTQuota, http.StatusUnauthorized: errVTAuth, http.StatusNotFound: nil} {
		status = code
		if _, err := e.lookupVT(context.Background(), "1.2.3.4"); !errors.Is(err, want) {
			t.Errorf("HTTP %d 得到 %v", code, err)
		}
	}
}

func TestVTBudget(t *testing.T) {
	now := time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)
	e := &Enricher{VTKey: "k", VTPerMin: 4, VTPerDay: 6}
	if n := e.vtBudget(now); n != 4 {
		t.Fatalf("每分钟上限 4，得到 %d", n)
	}
	e.usedToday = 5
	if n := e.vtBudget(now); n != 1 {
		t.Fatalf("当天只剩 1 次，得到 %d", n)
	}
	if n := e.vtBudget(now.Add(24 * time.Hour)); n != 4 {
		t.Fatalf("跨天应重置，得到 %d", n)
	}
	e.pauseTill = now.Add(48 * time.Hour)
	if n := e.vtBudget(now.Add(25 * time.Hour)); n != 0 {
		t.Fatalf("暂停期内不查，得到 %d", n)
	}
	if n := (&Enricher{VTPerMin: 4, VTPerDay: 500}).vtBudget(now); n != 0 {
		t.Fatalf("没配 key 不查，得到 %d", n)
	}
}
