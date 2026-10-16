package report

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
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

// 数字 IP 外链无需 DNS；用本地 HTTP 接收器验证真实 Chromium 不会请求它。
func TestPDFBlocksIPImages(t *testing.T) {
	if _, err := exec.LookPath(Chromium); err != nil {
		t.Skip("未安装 Chromium")
	}
	var requests atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.Write([]byte("image")) }))
	defer endpoint.Close()
	html, err := HTML("报告", "![外链]("+endpoint.URL+"/probe)", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pdf, err := PDF(context.Background(), html)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(pdf), "%PDF-") {
		t.Fatal("未生成 PDF")
	}
	if requests.Load() != 0 {
		t.Fatal("Chromium 访问了 IP 外链")
	}
}

func TestStandaloneHTMLHasCSP(t *testing.T) {
	html, err := HTML("报告", "![外链](http://127.0.0.1/probe)", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s := string(html)
	csp := strings.Index(s, `http-equiv="Content-Security-Policy"`)
	body := strings.Index(s, "<body>")
	if csp < 0 || csp > body || !strings.Contains(s, CSP) {
		t.Fatal("独立 HTML 缺少前置 CSP")
	}
}
