package beacon

import (
	"math/rand"
	"strings"
	"testing"
	"time"
)

func series(n int, gap time.Duration, jitter float64, seed int64) []time.Time {
	r := rand.New(rand.NewSource(seed))
	t := time.Unix(1_800_000_000, 0)
	out := []time.Time{t}
	for i := 1; i < n; i++ {
		d := float64(gap) * (1 + jitter*(2*r.Float64()-1))
		t = t.Add(time.Duration(d))
		out = append(out, t)
	}
	return out
}

func TestPeriodic(t *testing.T) {
	cases := []struct {
		name  string
		times []time.Time
		want  bool
	}{
		{"10 分钟定时", series(20, 10*time.Minute, 0, 1), true},
		{"60 秒心跳带 5% 抖动", series(120, time.Minute, 0.05, 2), true},
		{"抖动 50% 看不出规律", series(40, 10*time.Minute, 0.5, 3), false},
		{"次数不够", series(7, 10*time.Minute, 0, 4), false},
		{"比采样窗口还密", series(100, 20*time.Second, 0, 5), false},
		{"跨度不到一小时", series(10, 5*time.Minute, 0, 6), false},
		{"间隔超过上限", series(10, 2*time.Hour, 0, 7), false},
	}
	for _, c := range cases {
		if _, ok := Periodic(c.times); ok != c.want {
			p, _ := Periodic(c.times)
			t.Errorf("%s: 期望 %v，得到 %v（%+v）", c.name, c.want, ok, p)
		}
	}
	p, _ := Periodic(series(20, 10*time.Minute, 0, 1))
	if p.Median != 10*time.Minute || p.Spread != 0 || p.Hits != 20 {
		t.Fatalf("统计不对: %+v", p)
	}
}

func TestPublic(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1111": true, "::ffff:1.1.1.1": true,
		"10.1.1.4": false, "192.168.1.1": false, "172.16.5.5": false, "127.0.0.1": false,
		"100.64.1.1": false, "169.254.1.1": false, "fd00::1": false, "224.0.0.1": false, "": false, "x": false,
	} {
		if got := Public(ip); got != want {
			t.Errorf("%q: 期望 %v，得到 %v", ip, want, got)
		}
	}
}

func TestFlowAndDescribe(t *testing.T) {
	a := Conn{Container: "gateway", Process: "node", IP: "1.2.3.4", Port: "443", Host: "c2.example.com"}
	b := a
	b.IP = "5.6.7.8"
	b.Host = ""
	if a.Flow() != b.Flow() {
		t.Fatal("同一进程同一端口换了地址、没带域名，仍是同一条外联")
	}
	if (Conn{IP: "1.2.3.4", Port: "443"}).Flow() == (Conn{IP: "1.2.3.4", Port: "8443"}).Flow() {
		t.Fatal("端口不同应是不同外联")
	}
	p, _ := Periodic(series(20, 10*time.Minute, 0, 1))
	d := a.Describe(p)
	for _, want := range []string{"node（容器 gateway）", "约每 10 分钟连一次", "1.2.3.4:443（c2.example.com）", "20 次", "离散度 0.00"} {
		if !strings.Contains(d, want) {
			t.Errorf("详情缺 %q: %s", want, d)
		}
	}
}
