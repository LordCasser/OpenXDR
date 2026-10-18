package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"openxdr/server/internal/agentchat"
)

// SandboxTool 沙箱里的 xdr 命令行调用工具的入口。不走会话 cookie，只认会话工具令牌；
// 能做什么完全由令牌绑定的会话决定（组、发起人、名单与审批），与会话内的 Pi 相同
func SandboxTool(service *agentchat.Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "只接受 POST", http.StatusMethodNotAllowed)
			return
		}
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" || service == nil {
			http.Error(w, "缺少工具令牌", http.StatusUnauthorized)
			return
		}
		var body struct {
			Name string          `json:"name"`
			Args json.RawMessage `json:"args"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body) != nil {
			http.Error(w, "请求无效", http.StatusBadRequest)
			return
		}
		if len(body.Args) == 0 {
			body.Args = json.RawMessage("{}")
		}
		out, err := service.SandboxCall(r.Context(), token, body.Name, body.Args)
		switch {
		case agentchat.IsSandboxTokenError(err):
			http.Error(w, err.Error(), http.StatusUnauthorized)
		case err != nil:
			// 工具错误照样回给模型，让它看到原因后调整
			writeJSON(w, map[string]any{"error": err.Error()})
		default:
			writeJSON(w, map[string]any{"output": out})
		}
	})
}
