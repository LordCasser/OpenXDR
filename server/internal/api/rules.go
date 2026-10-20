package api

import (
	"net/http"
	"sort"

	"openxdr/server/internal/sigma"
)

type ruleRow struct {
	Kind          string   `json:"kind,omitempty"`
	WindowSeconds int      `json:"windowSeconds,omitempty"`
	Threshold     int      `json:"threshold,omitempty"`
	References    []string `json:"references,omitempty"`
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Author        string   `json:"author,omitempty"`
	Severity      int16    `json:"severity"`
	ClassUID      int      `json:"classUid"`
	Product       string   `json:"product"`
	// Signal 信号规则：只作时序规则输入，命中不单独告警
	Signal bool `json:"signal,omitempty"`
	// 该类别是否有采集源在供数：false 表示规则加载了但撞不到事件
	Ingested   bool     `json:"ingested"`
	Source     string   `json:"source"`
	Tactics    []string `json:"tactics"`
	Techniques []string `json:"techniques"`
}

// mapRules 检测面透明化：运营要能看到跑着哪些规则、哪些只是摆设。
func mapRules(api *http.ServeMux, rules sigma.Catalog) {
	api.HandleFunc("GET /api/rules", func(w http.ResponseWriter, r *http.Request) {
		all := rules.Rules()
		out := make([]ruleRow, len(all))
		available := map[string]bool{}
		for _, rule := range all {
			_, ok := sigma.IngestedClass(rule.ClassUID)
			available[rule.ID] = ok || rule.ClassUID == 0
		}
		for i, rule := range all {
			source, ingested := sigma.IngestedClass(rule.ClassUID)
			// 不限 class 的规则对所有事件求值，永远有数据
			if rule.ClassUID == 0 {
				ingested, source = true, "全部类别"
			}
			if rule.Kind != "" {
				source, ingested = "跨事件（依赖基础规则）", true
				for _, id := range rule.References {
					ingested = ingested && available[id]
				}
			}
			out[i] = ruleRow{
				Kind: rule.Kind, WindowSeconds: rule.WindowSeconds, Threshold: rule.Threshold, References: rule.References,
				ID: rule.ID, Title: rule.Title, Author: rule.Author, Severity: rule.Severity,
				ClassUID: rule.ClassUID, Product: rule.Product, Signal: rule.Signal,
				Ingested: ingested, Source: source,
				Tactics: rule.Tactics, Techniques: rule.Techniques,
			}
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Severity != out[j].Severity {
				return out[i].Severity > out[j].Severity
			}
			return out[i].Title < out[j].Title
		})
		writeJSON(w, out)
	})
}
