package api

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/auth"
)

type identityObservation struct {
	EventID uuid.UUID  `json:"eventId"`
	AssetID uuid.UUID  `json:"assetId"`
	GroupID *uuid.UUID `json:"groupId"`
	Ts      time.Time  `json:"ts"`
	SID     *string    `json:"sid"`
	Name    *string    `json:"name"`
	Domain  *string    `json:"domain"`
	LogonID *string    `json:"logonId"`
	Success *bool      `json:"success"`
	State   string     `json:"state"`
	Detail  string     `json:"detail"`
}

// IdentityObservations 返回资产上的来源观察；历史归组和当前归组必须同时可读。
func IdentityObservations(db *sql.DB) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/identity-observations", func(w http.ResponseWriter, r *http.Request) {
		u := auth.From(r.Context())
		if u == nil {
			http.Error(w, "请先登录", http.StatusUnauthorized)
			return
		}
		p := r.URL.Query()
		asset, err := uuid.Parse(p.Get("assetId"))
		if err != nil || asset == uuid.Nil {
			http.Error(w, "assetId 无效", http.StatusBadRequest)
			return
		}
		limit := 100
		if value := p.Get("limit"); value != "" {
			limit, err = strconv.Atoi(value)
			if err != nil || limit < 1 || limit > 200 {
				http.Error(w, "limit 必须为 1 到 200", http.StatusBadRequest)
				return
			}
		}
		to := time.Now()
		from := to.Add(-24 * time.Hour)
		for key, dest := range map[string]*time.Time{"from": &from, "to": &to} {
			if value := p.Get(key); value != "" {
				*dest, err = time.Parse(time.RFC3339Nano, value)
				if err != nil {
					http.Error(w, key+" 时间格式无效", http.StatusBadRequest)
					return
				}
			}
		}
		if from.After(to) {
			http.Error(w, "from 不能晚于 to", http.StatusBadRequest)
			return
		}
		// 在同一条 SQL 的快照中验证成员身份与资产归属，不复用预先取得的资产 ID 列表。
		rows, err := db.QueryContext(r.Context(), `SELECT i.event_id,i.asset_id,i.group_id,e.ts,
 i.account_sid,i.account_name,i.account_domain,i.logon_id,i.success,i.state,i.detail
 FROM identity_observations i JOIN events e ON e.id=i.event_id JOIN assets a ON a.id=i.asset_id JOIN users u ON u.id=$4
 WHERE i.asset_id=$1 AND e.ts >= $2 AND e.ts <= $3 AND (u.role='admin' OR (
 EXISTS (SELECT 1 FROM group_members m WHERE m.user_id=u.id AND m.group_id=i.group_id AND m.role IN ('viewer','analyst','admin')) AND
 EXISTS (SELECT 1 FROM group_members m WHERE m.user_id=u.id AND m.group_id=a.group_id AND m.role IN ('viewer','analyst','admin'))))
 ORDER BY e.ts DESC,i.event_id DESC LIMIT $5`, asset, from, to, u.ID, limit+1)
		if err != nil {
			http.Error(w, "身份观察查询失败", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		items := make([]identityObservation, 0)
		for rows.Next() {
			var row identityObservation
			if err := rows.Scan(&row.EventID, &row.AssetID, &row.GroupID, &row.Ts, &row.SID, &row.Name, &row.Domain, &row.LogonID, &row.Success, &row.State, &row.Detail); err != nil {
				http.Error(w, "身份观察读取失败", http.StatusInternalServerError)
				return
			}
			items = append(items, row)
		}
		if rows.Err() != nil {
			http.Error(w, "身份观察读取失败", http.StatusInternalServerError)
			return
		}
		truncated := len(items) > limit
		if truncated {
			items = items[:limit]
		}
		writeJSON(w, struct {
			Items     []identityObservation `json:"items"`
			Truncated bool                  `json:"truncated"`
		}{items, truncated})
	})
	return mux
}
