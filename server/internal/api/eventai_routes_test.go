package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// 按 main 的挂法：问 AI 的两个精确路径不能把 /api/events 本身吞掉（子树模式会把它重定向走）
func TestEventAIPathsKeepEventSearch(t *testing.T) {
	routes := http.NewServeMux()
	routes.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("X-Via", "main") }))
	ai := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("X-Via", "ai") })
	for _, p := range EventAIPaths {
		routes.Handle(p, ai)
	}
	for path, want := range map[string]string{
		"GET /api/events?q=x": "main",
		"GET /api/events/0190d7b0-0000-7000-8000-000000000000/related":  "ai",
		"POST /api/events/0190d7b0-0000-7000-8000-000000000000/explain": "ai",
	} {
		var method, url string
		for i := range path {
			if path[i] == ' ' {
				method, url = path[:i], path[i+1:]
				break
			}
		}
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, httptest.NewRequest(method, url, nil))
		if got := rec.Header().Get("X-Via"); got != want || rec.Code != http.StatusOK {
			t.Errorf("%s 应走 %s，得到 %q（%d）", path, want, got, rec.Code)
		}
	}
}
