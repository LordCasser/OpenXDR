// Package beacon 外联心跳检测：同一进程隔着差不多的时间反复连同一个公网目的地，是 C2 心跳的典型样子。
//
// 只看规律会被淹没——监控、NTP、软件更新检查本来就很规律（生产两台主机一天就有一百七十多条）。
// 能区分 C2 的是「这条规律外联是新冒出来的」：见过的心跳记进基线，资产接入满学习期后
// 新出现的才告警，告警照常进关联与 AI 研判。首次启用时回放学习期内的历史，只学不报。
//
// agent 按（目的地址, 端口）60 秒内只报一次连接，比这更密的连接看起来也像每分钟一次，测不出真实周期；
// 间隔超过 90 分钟的在 12 小时窗口里凑不够次数，看不到。
package beacon

import (
	"fmt"
	"net/netip"
	"slices"
	"time"
)

const (
	// MinGap agent 同一目标 60 秒只报一次，服务端看到的间隔不会更短；留 10 秒给心跳本身的抖动。
	// 比采样窗口更密的正常轮询也会被压成约每分钟一次，挡住它们靠的是基线（见过就不报），不是这个下限
	MinGap = 50 * time.Second
	// MaxGap 12 小时窗口里至少要有 MinHits 次
	MaxGap = 90 * time.Minute
	// MinHits 至少这么多次连接才谈得上规律
	MinHits = 8
	// MinSpan 连续出现至少这么久，几分钟内的连发不算
	MinSpan = time.Hour
	// MaxSpread 间隔四分位距与中位数之比的上限：越小越像定时器
	MaxSpread = 0.2
)

// Pattern 一条外联的到达间隔统计
type Pattern struct {
	Hits   int
	Median time.Duration
	Spread float64
	First  time.Time
	Last   time.Time
}

// Periodic 判定一组连接时刻是否像心跳。times 需已按时间排序
func Periodic(times []time.Time) (Pattern, bool) {
	p := Pattern{Hits: len(times)}
	if len(times) < MinHits {
		return p, false
	}
	p.First, p.Last = times[0], times[len(times)-1]
	gaps := make([]float64, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		gaps = append(gaps, times[i].Sub(times[i-1]).Seconds())
	}
	slices.Sort(gaps)
	med := quantile(gaps, 0.5)
	p.Median = time.Duration(med * float64(time.Second))
	if med <= 0 {
		return p, false
	}
	p.Spread = (quantile(gaps, 0.75) - quantile(gaps, 0.25)) / med
	ok := p.Median >= MinGap && p.Median <= MaxGap && p.Last.Sub(p.First) >= MinSpan && p.Spread <= MaxSpread
	return p, ok
}

// quantile 线性插值分位数，sorted 已升序且非空
func quantile(sorted []float64, q float64) float64 {
	pos := q * float64(len(sorted)-1)
	lo := int(pos)
	if lo+1 >= len(sorted) {
		return sorted[lo]
	}
	return sorted[lo] + (pos-float64(lo))*(sorted[lo+1]-sorted[lo])
}

// Public 只看公网目的地：内网的周期连接（监控抓取、数据库连接池）是心跳检测最大的噪声源
func Public(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a)
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Conn 一次出站连接里心跳检测用得到的字段
type Conn struct {
	Container string
	Process   string
	IP        string
	Port      string
	Host      string
}

// Flow 外联的身份：容器、进程与目的端口。目的地址当身份太不稳——中继服务换着地址连、
// 同一目的地有时带域名有时不带，生产数据里按地址认每天多出十几条「新心跳」；按进程与端口认只剩几条。
// 代价是注入进本来就规律连同一端口的进程看不出来，新落地的程序、老程序连新端口都能抓到
func (c Conn) Flow() string {
	return c.Container + "|" + c.Process + "|" + c.Port
}

// Describe 告警详情：一行人读的依据，研判和事件页都看这一行
func (c Conn) Describe(p Pattern) string {
	dst := c.IP + ":" + c.Port
	if c.Host != "" {
		dst += "（" + c.Host + "）"
	}
	who := c.Process
	if who == "" {
		who = "未知进程"
	}
	if c.Container != "" {
		who += "（容器 " + c.Container + "）"
	}
	return fmt.Sprintf("%s 约每 %s连一次公网 %s：%s内 %d 次，间隔中位 %.0f 秒、离散度 %.2f；此前没有见过这个进程在这个端口上的周期外联",
		who, human(p.Median), dst, human(p.Last.Sub(p.First)), p.Hits, p.Median.Seconds(), p.Spread)
}

func human(d time.Duration) string {
	switch {
	case d >= time.Hour:
		return fmt.Sprintf("%.1f 小时", d.Hours())
	case d >= time.Minute:
		return fmt.Sprintf("%.0f 分钟", d.Minutes())
	default:
		return fmt.Sprintf("%.0f 秒", d.Seconds())
	}
}
