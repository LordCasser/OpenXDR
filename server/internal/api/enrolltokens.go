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
	Kind      string    `json:"kind"`
	CreatedBy string    `json:"createdBy"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Revoked   bool      `json:"revoked"`
	Uses      int       `json:"uses"`
	// 明文只在创建时返回一次
	Token string `json:"token,omitempty"`
}

func tokenRow(t *ent.EnrollToken) enrollTokenRow {
	return enrollTokenRow{t.ID, t.GroupID, string(t.Kind), t.CreatedBy, t.CreatedAt, t.ExpiresAt, t.Revoked, t.Uses, ""}
}

// EnrollTokens 接入令牌管理：组 admin 为本组签发与撤销 agent 令牌，状态接口告诉前端能不能在线接入。
//
// 流量探针令牌只有全局 admin 能签：探针看到的是整段网络的流量，会话按地址归属到任意组的资产上，
// 组 admin 不能借本组的令牌放一台探针去给别的组灌数据。探针所在主机本身仍归入令牌所属组。
func EnrollTokens(db *ent.Client, svc *enroll.Service, dists enroll.Dists) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/enroll-tokens/status", func(w http.ResponseWriter, r *http.Request) {
		platforms := dists.Agent.Available()
		reason := svc.Disabled()
		if reason == "" && len(platforms) == 0 {
			reason = "server 未提供 agent 安装包（AGENT_DIST_DIR 未配置或为空）"
		}
		writeJSON(w, map[string]any{"enabled": reason == "", "reason": reason, "platforms": platforms,
			"sensorPlatforms": dists.Sensor.Available()})
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
			Kind    string    `json:"kind"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "请求体不是合法 JSON", http.StatusBadRequest)
			return
		}
		if body.Days == 0 {
			body.Days = 7
		}
		if body.Kind == "" {
			body.Kind = enroll.KindAgent
		}
		if !requireGroup(w, r, db, body.GroupID, "admin") {
			return
		}
		if body.Kind == enroll.KindSensor && auth.From(r.Context()).Role != "admin" {
			http.Error(w, "流量探针令牌只有平台管理员能签发", http.StatusForbidden)
			return
		}
		plain, t, err := svc.IssueKind(r.Context(), body.Kind, body.GroupID, auth.From(r.Context()).Username, time.Duration(body.Days)*24*time.Hour)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		audit.Log(r.Context(), db, r, "enroll_token_created", t.ID.String(), fmt.Sprintf("组 %s，%s，%d 天", body.GroupID, body.Kind, body.Days))
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
