package memories

import (
	"strings"
	"testing"
)

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
