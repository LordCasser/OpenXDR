package report

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestHTMLEscapesUntrustedMarkdown(t *testing.T) {
	out, err := HTML("巡检 <b>", "# 结论\n\n<script>alert(1)</script>\n\n[x](javascript:alert(1))\n\n| 主机 | 状态 |\n|---|---|\n| web01 | 正常 |\n", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, bad := range []string{"<script>", "javascript:", "<b>"} {
		if strings.Contains(s, bad) {
			t.Errorf("输出不应包含 %q", bad)
		}
	}
	for _, want := range []string{"<h1>结论</h1>", "<table>", "巡检 &lt;b&gt;"} {
		if !strings.Contains(s, want) {
			t.Errorf("输出缺少 %q", want)
		}
	}
}

func TestPDFWithoutChromium(t *testing.T) {
	old := Chromium
	Chromium = "openxdr-no-such-chromium"
	defer func() { Chromium = old }()
	_, err := PDF(context.Background(), []byte("<p>x</p>"))
	if !errors.Is(err, ErrNoChromium) {
		t.Fatalf("缺 Chromium 应报 ErrNoChromium，得到 %v", err)
	}
}
