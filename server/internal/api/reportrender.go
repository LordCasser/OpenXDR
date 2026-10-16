package api

import (
	"errors"
	"fmt"
	"net/http"

	"openxdr/server/ent"
	"openxdr/server/internal/report"
)

// 报告正文出自模型：页面不许跑脚本、不许外链，只留内联样式
const reportCSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox"

// mapReportRender Pi 报告按需渲染成 HTML / PDF，权限与 GET /api/agent-reports/{id} 一致。
func mapReportRender(api *http.ServeMux, db *ent.Client) {
	render := func(w http.ResponseWriter, r *http.Request) (*ent.Report, []byte, bool) {
		row, ok := getByPath(w, r, "id", "report", db.Report.Get)
		if !ok || !requireGroup(w, r, db, row.GroupID, "viewer") {
			return nil, nil, false
		}
		html, err := report.HTML(row.Title, row.Markdown, row.CreatedAt)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return nil, nil, false
		}
		w.Header().Set("Content-Security-Policy", reportCSP)
		return row, html, true
	}

	api.HandleFunc("GET /api/agent-reports/{id}/html", func(w http.ResponseWriter, r *http.Request) {
		if _, html, ok := render(w, r); ok {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(html)
		}
	})

	api.HandleFunc("GET /api/agent-reports/{id}/pdf", func(w http.ResponseWriter, r *http.Request) {
		row, html, ok := render(w, r)
		if !ok {
			return
		}
		pdf, err := report.PDF(r.Context(), html)
		if errors.Is(err, report.ErrNoChromium) {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="report-%s.pdf"`, row.ID))
		_, _ = w.Write(pdf)
	})
}
