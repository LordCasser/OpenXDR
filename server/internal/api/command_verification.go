package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/google/uuid"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/response"
)

func CommandVerifications(db *sql.DB) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/commands/{id}/verifications", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "方法不支持", http.StatusMethodNotAllowed)
			return
		}
		u := auth.From(r.Context())
		if u == nil {
			http.Error(w, "请先登录", http.StatusUnauthorized)
			return
		}
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil || id == uuid.Nil {
			http.Error(w, "无效的指令 ID", http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodGet {
			items, err := response.ListVerifications(r.Context(), db, u.ID, id)
			if err != nil {
				http.Error(w, "读取复核记录失败", http.StatusInternalServerError)
				return
			}
			truncated := len(items) > 100
			if truncated {
				items = items[:100]
			}
			writeJSON(w, struct {
				Items     []response.Verification `json:"items"`
				Truncated bool                    `json:"truncated"`
			}{items, truncated})
			return
		}
		var in response.VerificationInput
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&in); err != nil {
			http.Error(w, "复核请求格式无效", http.StatusBadRequest)
			return
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			http.Error(w, "复核请求含多余数据", http.StatusBadRequest)
			return
		}
		out, err := response.RecordVerification(r.Context(), db, u.ID, id, in)
		switch {
		case errors.Is(err, response.ErrVerificationScope):
			http.Error(w, "无指令复核权限或指令不存在", http.StatusForbidden)
		case errors.Is(err, response.ErrVerificationInput):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case err != nil:
			http.Error(w, "保存复核失败", http.StatusInternalServerError)
		default:
			writeJSON(w, out)
		}
	})
	mux.HandleFunc("GET /api/commands/{id}/verifications/{verificationId}", func(w http.ResponseWriter, r *http.Request) {
		u := auth.From(r.Context())
		if u == nil {
			http.Error(w, "请先登录", http.StatusUnauthorized)
			return
		}
		commandID, err := uuid.Parse(r.PathValue("id"))
		if err != nil || commandID == uuid.Nil {
			http.Error(w, "无效的指令 ID", http.StatusBadRequest)
			return
		}
		verificationID, err := uuid.Parse(r.PathValue("verificationId"))
		if err != nil || verificationID == uuid.Nil {
			http.Error(w, "无效的复核 ID", http.StatusBadRequest)
			return
		}
		item, err := response.GetVerification(r.Context(), db, u.ID, commandID, verificationID)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			http.NotFound(w, r)
		case err != nil:
			http.Error(w, "读取复核证据失败", http.StatusInternalServerError)
		default:
			writeJSON(w, item)
		}
	})
	return mux
}
