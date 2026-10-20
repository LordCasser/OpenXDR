package memories

import (
	"strings"
	"testing"
	"time"
)

func TestReview(t *testing.T) {
	now := time.Now()
	fresh, stale := now.Add(-time.Hour), now.Add(-ReviewAfter-time.Hour)
	negatives := []string{
		"pve2 宿主机在线核实不了 RAID BBU 状态：无 storcli/perccli/MegaCli",
		"gw1 上没有 smartctl 工具，磁盘健康看不到",
		"沙箱里无法访问外网",
		"dns1 未安装 ss，用 netstat",
		"storcli: command not found on pve1",
		"cannot read /var/log/secure without root",
	}
	for _, c := range negatives {
		if Review("ai", c, fresh, now) == "" {
			t.Errorf("AI 写的否定性结论应标待复核：%s", c)
		}
		if Review("human", c, stale, now) != "" {
			t.Errorf("人工记忆不应被标：%s", c)
		}
	}
	facts := []string{"pve1 每天 04:30 跑 vzdump 备份到 nas1", "10.1.1.53 是内网 DNS 容器", "backup 主机凌晨 CPU 高是 rsync，不能当异常"}
	for _, c := range facts {
		if note := Review("ai", c, fresh, now); note != "" {
			t.Errorf("新近的事实记忆不应标：%s → %s", c, note)
		}
		if Review("ai", c, stale, now) == "" {
			t.Errorf("超过复核期的 AI 记忆应标：%s", c)
		}
		if Review("human", c, stale, now) != "" {
			t.Errorf("人工记忆不受复核期影响：%s", c)
		}
	}
}

func TestClean(t *testing.T) {
	ok := map[string]string{
		"  每天 04:30 跑巡检  ":            "每天 04:30 跑巡检",
		"\n\t网关是 10.1.1.1\r\n":        "网关是 10.1.1.1",
		"中间的  空白\n保留":                 "中间的  空白\n保留",
		strings.Repeat("长", MaxRunes): strings.Repeat("长", MaxRunes),
		// 首尾空白不计入长度
		"  " + strings.Repeat("a", MaxRunes) + "  ": strings.Repeat("a", MaxRunes),
	}
	for in, want := range ok {
		got, err := Clean(in)
		if err != nil || got != want {
			t.Errorf("Clean(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	// 按字符而不是字节计长：500 个汉字是 1500 字节，仍应接受；501 个拒绝
	bad := map[string]string{
		"空串":       "",
		"全空白":      " \t\n　",
		"超长汉字":     strings.Repeat("长", MaxRunes+1),
		"超长 ASCII": strings.Repeat("a", MaxRunes+1),
	}
	for name, in := range bad {
		if got, err := Clean(in); err == nil {
			t.Errorf("%s 应被拒绝，实际 %q", name, got)
		}
	}
}
