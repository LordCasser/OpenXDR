package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/enrolltoken"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/enroll"
)

type enrollTokenRow struct {
	ID        uuid.UUID `json:"id"`
	GroupID   uuid.UUID `json:"groupId"`
	CreatedBy string    `json:"createdBy"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Revoked   bool      `json:"revoked"`
	Uses      int       `json:"uses"`
	// 明文只在创建时返回一次
	Token string `json:"token,omitempty"`
}

func tokenRow(t *ent.EnrollToken) enrollTokenRow {
	return enrollTokenRow{t.ID, t.GroupID, t.CreatedBy, t.CreatedAt, t.ExpiresAt, t.Revoked, t.Uses, ""}
}

// EnrollTokens 接入令牌管理：组 admin 为本组签发与撤销，状态接口告诉前端能不能在线接入。
func EnrollTokens(db *ent.Client, svc *enroll.Service, dist *enroll.Dist) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/enroll-tokens/status", func(w http.ResponseWriter, r *http.Request) {
		platforms := dist.Available()
		reason := svc.Disabled()
		if reason == "" && len(platforms) == 0 {
			reason = "server 未提供 agent 安装包（AGENT_DIST_DIR 未配置或为空）"
		}
		writeJSON(w, map[string]any{"enabled": reason == "", "reason": reason, "platforms": platforms})
	})
	mux.HandleFunc("GET /api/enroll-tokens", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.URL.Query().Get("groupId"))
		if err != nil {
			http.Error(w, "groupId 必填", http.StatusBadRequest)
			return
		}
		if !requireGroup(w, r, db, id, "admin") {
			return
		}
		rows, err := db.EnrollToken.Query().Where(enrolltoken.GroupIDEQ(id)).
			Order(ent.Desc(enrolltoken.FieldCreatedAt)).Limit(100).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]enrollTokenRow, len(rows))
		for i, t := range rows {
			out[i] = tokenRow(t)
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("POST /api/enroll-tokens", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			GroupID uuid.UUID `json:"groupId"`
			Days    int       `json:"days"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "请求体不是合法 JSON", http.StatusBadRequest)
			return
		}
		if body.Days == 0 {
			body.Days = 7
		}
		if !requireGroup(w, r, db, body.GroupID, "admin") {
			return
		}
		plain, t, err := svc.Issue(r.Context(), body.GroupID, auth.From(r.Context()).Username, time.Duration(body.Days)*24*time.Hour)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		audit.Log(r.Context(), db, r, "enroll_token_created", t.ID.String(), fmt.Sprintf("组 %s，%d 天", body.GroupID, body.Days))
		row := tokenRow(t)
		row.Token = plain
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, row)
	})
	mux.HandleFunc("DELETE /api/enroll-tokens/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		t, err := db.EnrollToken.Get(r.Context(), id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if !requireGroup(w, r, db, t.GroupID, "admin") {
			return
		}
		if err := db.EnrollToken.UpdateOne(t).SetRevoked(true).Exec(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, "enroll_token_revoked", t.ID.String(), "")
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}
