package triage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// 关思考只对 GLM 生效，其他端点不认这个参数；输出上限对所有端点生效
func TestNoThinkingOnlyForGLM(t *testing.T) {
	for _, c := range []struct {
		model string
		want  bool
	}{{"GLM-5.3-Flash", true}, {"zai/glm-4.6", true}, {"qwen3", false}, {"gpt-glmish", false}} {
		var got map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&got)
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{}"}}]}`))
		}))
		l := NewLLM(srv.URL, c.model, "", time.Second)
		l.NoThinking, l.MaxTokens = true, 2048
		if _, err := l.Chat(context.Background(), []Message{{Role: "user", Content: "x"}}, nil); err != nil {
			t.Fatal(err)
		}
		srv.Close()
		if _, ok := got["chat_template_kwargs"]; ok != c.want || got["max_tokens"] != float64(2048) {
			t.Errorf("%s: kwargs=%v max_tokens=%v", c.model, got["chat_template_kwargs"], got["max_tokens"])
		}
	}
}
