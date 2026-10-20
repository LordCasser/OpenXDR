package report

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// 报告统一格式：标题与一句话结论由平台渲染在页头，正文按固定的二级标题分节。
// 结论、需要人处理、未验证三节必须有（没有就写「无」），读的人每份报告都在同一个位置找到同一类信息。
const (
	MaxTitle   = 50
	MaxSummary = 120
)

// Sections 正文的节，按这个顺序写；Required 为必须出现的节
var (
	Sections = []string{"结论", "需要人处理", "证据", "推断", "未验证", "已执行的操作"}
	Required = []string{"结论", "需要人处理", "未验证"}
)

// Template 给模型看的正文骨架，报告不合格时原样带回去
const Template = `## 结论
定性与关键理由，一两段。
## 需要人处理
逐条写事项、主机、严重程度与建议；巡检分「新增 / 仍未解决 / 本轮已修复」三个三级标题。没有写「无」。
## 证据
已观察到的事实，标明主机与来源命令或查询；多台主机按主机分三级标题。
## 推断
基于证据的判断与把握程度，没有可省略。
## 未验证
没覆盖到、等待批准或执行失败的检查项。没有写「无」。
## 已执行的操作
改动、登记的待办、提交的抑制或结案建议；只读排查写「无」，可省略。`

var (
	h1      = regexp.MustCompile(`^#\s+\S`)
	section = regexp.MustCompile(`(?m)^##\s+(.+?)\s*$`)
)

// Normalize 校验并整理一份报告：标题与结论去掉首尾空白并限长，正文去掉模型自己写的一级标题（页头已经有标题），
// 必需的节缺了就拒绝并带回骨架。返回值可直接入库。
func Normalize(title, summary, markdown string) (string, string, string, error) {
	title, summary = strings.TrimSpace(title), strings.TrimSpace(summary)
	if n := utf8.RuneCountInString(title); n == 0 || n > MaxTitle {
		return "", "", "", fmt.Errorf("标题须为 1–%d 字（现在 %d 字）：写成「对象 + 主题」，比如「pve1/pve2 每日巡检」，结论放 summary", MaxTitle, n)
	}
	if n := utf8.RuneCountInString(summary); n == 0 || n > MaxSummary || strings.ContainsAny(summary, "\r\n") {
		return "", "", "", fmt.Errorf("summary 须为一句话结论，1–%d 字、不换行（现在 %d 字），比如「pve2 RAID 电池故障待更换，其余正常」", MaxSummary, n)
	}
	markdown = stripTitle(markdown)
	if markdown == "" || len(markdown) > 262144 {
		return "", "", "", errors.New("正文长度无效")
	}
	have := map[string]bool{}
	for _, m := range section.FindAllStringSubmatch(markdown, -1) {
		for _, name := range Sections {
			if strings.HasPrefix(strings.TrimLeft(m[1], "一二三四五六七八九十、.0123456789 "), name) {
				have[name] = true
			}
		}
	}
	var missing []string
	for _, name := range Required {
		if !have[name] {
			missing = append(missing, "## "+name)
		}
	}
	if len(missing) > 0 {
		return "", "", "", fmt.Errorf("正文缺少 %s。按这个骨架分节（二级标题照写，节内自由组织）：\n%s", strings.Join(missing, "、"), Template)
	}
	return title, summary, markdown, nil
}

// stripTitle 去掉正文开头的一级标题：标题由平台渲染，正文里再写一遍就重复了
func stripTitle(markdown string) string {
	markdown = strings.TrimSpace(markdown)
	if first, rest, _ := strings.Cut(markdown, "\n"); h1.MatchString(first) {
		return strings.TrimSpace(rest)
	}
	return markdown
}
