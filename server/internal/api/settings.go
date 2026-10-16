package api

import (
	"encoding/json"
	"net/http"
	"net/url"

	"openxdr/server/ent"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/notify"
)

var notifyFormats = map[string]bool{"generic": true, "dingtalk": true, "feishu": true, "wecom": true}

// Settings 控制台可改的运行时配置，只有 admin 能动（门槛见 auth.minRole）。
func Settings(db *ent.Client, settings *notify.Settings, webhook *notify.Webhook) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/settings/notify", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, settings.Load(r.Context()))
	})
	mux.HandleFunc("PUT /api/settings/notify", func(w http.ResponseWriter, r *http.Request) {
		t, ok := decodeTarget(w, r)
		if !ok {
			return
		}
		if err := settings.Save(r.Context(), t); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// 地址里可能带 token，审计只记格式与开关
		detail, _ := json.Marshal(map[string]any{"enabled": t.URL != "", "format": t.Format, "minSeverity": t.MinSeverity})
		audit.Log(r.Context(), db, r, "notify_settings_updated", "notify", string(detail))
		writeJSON(w, t)
	})
	// 用表单里还没保存的配置发一条，先验证再保存
	mux.HandleFunc("POST /api/settings/notify/test", func(w http.ResponseWriter, r *http.Request) {
		t, ok := decodeTarget(w, r)
		if !ok {
			return
		}
		if t.URL == "" {
			http.Error(w, "未填写推送地址", http.StatusBadRequest)
			return
		}
		if err := webhook.SendTo(r.Context(), t, "测试消息", "收到这条说明 OpenXDR 通知已接通。", "/"); err != nil {
			http.Error(w, "推送失败："+err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func decodeTarget(w http.ResponseWriter, r *http.Request) (notify.Target, bool) {
	var t notify.Target
	if json.NewDecoder(r.Body).Decode(&t) != nil {
		http.Error(w, "请求体不是合法 JSON", http.StatusBadRequest)
		return t, false
	}
	if t.Format == "" {
		t.Format = "generic"
	}
	if !notifyFormats[t.Format] {
		http.Error(w, "format 只能是 generic / dingtalk / feishu / wecom", http.StatusBadRequest)
		return t, false
	}
	for _, raw := range []string{t.URL, t.LinkBase} {
		if raw == "" {
			continue
		}
		if u, err := url.Parse(raw); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			http.Error(w, "地址必须是 http(s) 链接："+raw, http.StatusBadRequest)
			return t, false
		}
	}
	if t.MinSeverity < 0 || t.MinSeverity > 5 {
		http.Error(w, "minSeverity 取 0–5", http.StatusBadRequest)
		return t, false
	}
	return t, true
}
