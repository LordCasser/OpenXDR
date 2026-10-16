package enroll

import (
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"openxdr/server/internal/audit"
)

//go:embed install.sh
var installSh []byte

//go:embed install.ps1
var installPs1 []byte

// Platforms 可分发的 agent 平台与 AGENT_DIST_DIR 里的文件名。
var Platforms = map[string]string{
	"linux-amd64":   "openxdr-agent-linux-amd64",
	"linux-arm64":   "openxdr-agent-linux-arm64",
	"windows-amd64": "openxdr-agent-windows-amd64.exe",
}

// Available AGENT_DIST_DIR 里实际放了二进制的平台。
func Available(distDir string) []string {
	var out []string
	for p, name := range Platforms {
		if distDir == "" {
			break
		}
		if st, err := os.Stat(filepath.Join(distDir, name)); err == nil && st.Mode().IsRegular() {
			out = append(out, p)
		}
	}
	return out
}

// Public 免登录的接入端点：安装脚本、agent 二进制与注册。注册靠令牌鉴权。
func (s *Service) Public(distDir string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/enroll/install.sh", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		_, _ = w.Write(installSh)
	})
	mux.HandleFunc("GET /api/enroll/install.ps1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(installPs1)
	})
	mux.HandleFunc("GET /api/enroll/agent/{platform}", func(w http.ResponseWriter, r *http.Request) {
		name, ok := Platforms[r.PathValue("platform")]
		if !ok || distDir == "" {
			http.Error(w, "server 未提供该平台的 agent（检查 AGENT_DIST_DIR）", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, filepath.Join(distDir, name))
	})
	mux.HandleFunc("POST /api/enroll/register", func(w http.ResponseWriter, r *http.Request) {
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		var req Request
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
			http.Error(w, "接入请求不是合法 JSON", http.StatusBadRequest)
			return
		}
		a, grant, err := s.Enroll(r.Context(), token, req)
		switch {
		case errors.Is(err, ErrToken):
			http.Error(w, err.Error(), http.StatusUnauthorized)
		case errors.Is(err, ErrOnline), errors.Is(err, ErrMoved):
			http.Error(w, err.Error(), http.StatusConflict)
		case errors.Is(err, ErrHostname):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case err != nil && s.Disabled() != "":
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		case err != nil:
			slog.Error("主机接入失败", "hostname", req.Hostname, "err", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
		default:
			audit.Log(r.Context(), s.DB, r, "host_enrolled", a.ID.String(), req.Hostname)
			slog.Info("主机已接入", "hostname", req.Hostname, "group", a.GroupID)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(grant)
		}
	})
	return mux
}
