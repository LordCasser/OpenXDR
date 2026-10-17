// Package redact 入库前抹掉事件文本里的凭据。
//
// 命令行、日志里常有写死的 token 与口令（git 镜像把 token 拼进 URL 就是典型）。
// 事件会保留 30 天，还会作为证据送进模型，凭据一旦入库就等于扩散。
// 只认格式明确的几类，宁可漏抹也不改坏正常文本——检测规则还要在这份文本上求值。
package redact

import "regexp"

// Mask 替换掉凭据后留下的标记。
const Mask = "***"

var rules = []struct {
	re   *regexp.Regexp
	repl string
}{
	// URL 里的 userinfo：https://token@host、https://user:password@host
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)([^\s/@:]+):[^\s/@]+@`), "${1}${2}:" + Mask + "@"},
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/@:]+@`), "${1}" + Mask + "@"},
	// 带固定前缀的平台 token
	{regexp.MustCompile(`\b(gh[pousr]_|github_pat_|glpat-|xox[abprs]-)[A-Za-z0-9_-]{16,}`), "${1}" + Mask},
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "AKIA" + Mask},
	{regexp.MustCompile(`\bsk-(ant-)?[A-Za-z0-9_-]{20,}`), "sk-${1}" + Mask},
	// 长选项传口令：--password=x、--token x
	{regexp.MustCompile(`(?i)(--(?:password|passwd|token|secret|api-?key|access-key)[= ])("[^"]*"|'[^']*'|\S+)`), "${1}" + Mask},
}

// String 返回抹掉凭据后的文本；没有命中时原样返回。
func String(s string) string {
	for _, r := range rules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}
