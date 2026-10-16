// Package report 报告渲染：Pi 提交的 Markdown 转 HTML，再交给 headless Chromium 打印成 PDF。
// Markdown 来自模型，视为不可信输入：goldmark 默认不输出原始 HTML、滤掉 javascript: 等危险链接，
// 页面再由调用方加 CSP 兜底。
package report

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
)

var md = goldmark.New(goldmark.WithExtensions(extension.GFM))

var page = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>{{.Title}}</title>
<style>
body{font-family:"Noto Sans CJK SC","PingFang SC","Microsoft YaHei",sans-serif;max-width:960px;margin:2em auto;padding:0 1em;color:#1f2328;line-height:1.6}
h1,h2,h3{border-bottom:1px solid #d0d7de;padding-bottom:.3em}
table{border-collapse:collapse;margin:1em 0}th,td{border:1px solid #d0d7de;padding:4px 10px}th{background:#f6f8fa}
code{background:#f6f8fa;padding:.1em .3em;border-radius:4px;font-size:90%}
pre{background:#f6f8fa;padding:1em;overflow-x:auto}pre code{background:none;padding:0}
.meta{color:#656d76;font-size:90%}
@media print{body{margin:0;max-width:none}pre{white-space:pre-wrap}}
</style></head><body>
<h1>{{.Title}}</h1>
<p class="meta">生成时间 {{.CreatedAt.Format "2006-01-02 15:04:05"}}</p>
{{.Body}}
</body></html>
`))

// HTML 渲染成独立页面。
func HTML(title, markdown string, createdAt time.Time) ([]byte, error) {
	var body bytes.Buffer
	if err := md.Convert([]byte(markdown), &body); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	err := page.Execute(&out, struct {
		Title     string
		CreatedAt time.Time
		Body      template.HTML // goldmark 已转义，原始 HTML 被省略
	}{title, createdAt, template.HTML(body.String())})
	return out.Bytes(), err
}

// Chromium 可执行文件名或路径，main 按 CHROMIUM_PATH 设置。
var Chromium = "chromium"

// ErrNoChromium 未找到 Chromium，PDF 不可用。
var ErrNoChromium = errors.New("未找到 Chromium，PDF 渲染不可用")

// PDF 用 headless Chromium 打印 HTML。
// 网络全部禁掉：报告是自包含页面，不该有任何外部请求。
func PDF(ctx context.Context, html []byte) ([]byte, error) {
	bin, err := exec.LookPath(Chromium)
	if err != nil {
		return nil, ErrNoChromium
	}
	dir, err := os.MkdirTemp("", "openxdr-report-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	in, out := filepath.Join(dir, "report.html"), filepath.Join(dir, "report.pdf")
	if err := os.WriteFile(in, html, 0o600); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin,
		"--headless", "--no-sandbox", "--disable-gpu", "--no-pdf-header-footer",
		"--user-data-dir="+filepath.Join(dir, "profile"),
		// 只允许解析到本地，挡掉报告里任何外链请求
		"--host-resolver-rules=MAP * ~NOTFOUND",
		"--print-to-pdf="+out, "file://"+in)
	if msg, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("chromium 渲染失败: %w: %s", err, tail(msg))
	}
	return os.ReadFile(out)
}

func tail(b []byte) []byte {
	if len(b) > 512 {
		return b[len(b)-512:]
	}
	return b
}
