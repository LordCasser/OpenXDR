package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/auth"
)

type localAccountSnapshot struct {
	EventID      uuid.UUID  `json:"eventId"`
	AssetID      uuid.UUID  `json:"assetId"`
	GroupID      *uuid.UUID `json:"groupId"`
	Ts           time.Time  `json:"ts"`
	State        string     `json:"state"`
	Source       string     `json:"source"`
	AccountCount *int       `json:"accountCount"`
}

// LocalAccountSnapshots 返回资产上的来源观察；历史归组和当前归组必须同时可读。
func LocalAccountSnapshots(db *sql.DB) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/local-account-snapshots", func(w http.ResponseWriter, r *http.Request) {
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
 i.state,i.source,CASE WHEN i.state='observed' THEN (SELECT count(*) FROM identity_local_accounts c WHERE c.event_id=i.event_id) ELSE NULL END
 FROM identity_local_snapshots i JOIN events e ON e.id=i.event_id JOIN assets a ON a.id=i.asset_id JOIN users u ON u.id=$4
 WHERE i.asset_id=$1 AND e.ts >= $2 AND e.ts <= $3 AND (u.role='admin' OR (
 EXISTS (SELECT 1 FROM group_members m WHERE m.user_id=u.id AND m.group_id=i.group_id AND m.role IN ('viewer','analyst','admin')) AND
 EXISTS (SELECT 1 FROM group_members m WHERE m.user_id=u.id AND m.group_id=a.group_id AND m.role IN ('viewer','analyst','admin'))))
 ORDER BY e.ts DESC,i.event_id DESC LIMIT $5`, asset, from, to, u.ID, limit+1)
		if err != nil {
			http.Error(w, "本地账号快照查询失败", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		items := make([]localAccountSnapshot, 0)
		for rows.Next() {
			var row localAccountSnapshot
			if err := rows.Scan(&row.EventID, &row.AssetID, &row.GroupID, &row.Ts, &row.State, &row.Source, &row.AccountCount); err != nil {
				http.Error(w, "本地账号快照读取失败", http.StatusInternalServerError)
				return
			}
			items = append(items, row)
		}
		if rows.Err() != nil {
			http.Error(w, "本地账号快照读取失败", http.StatusInternalServerError)
			return
		}
		truncated := len(items) > limit
		if truncated {
			items = items[:limit]
		}
		writeJSON(w, struct {
			Items     []localAccountSnapshot `json:"items"`
			Truncated bool                   `json:"truncated"`
		}{items, truncated})
	})
	mux.HandleFunc("GET /api/local-account-snapshots/{eventId}", func(w http.ResponseWriter, r *http.Request) {
		u := auth.From(r.Context())
		if u == nil {
			http.Error(w, "请先登录", http.StatusUnauthorized)
			return
		}
		id, err := uuid.Parse(r.PathValue("eventId"))
		if err != nil || id == uuid.Nil {
			http.Error(w, "eventId 无效", http.StatusBadRequest)
			return
		}
		var result struct {
			localAccountSnapshot
			Items json.RawMessage `json:"items"`
		}
		err = db.QueryRowContext(r.Context(), `SELECT i.event_id,i.asset_id,i.group_id,e.ts,i.state,i.source,
   CASE WHEN i.state='observed' THEN jsonb_array_length(d.items) ELSE NULL END,
   CASE WHEN i.state='observed' THEN d.items ELSE 'null'::jsonb END
   FROM identity_local_snapshots i JOIN events e ON e.id=i.event_id JOIN assets a ON a.id=i.asset_id
   JOIN users u ON u.id=$2
   CROSS JOIN LATERAL (SELECT COALESCE(jsonb_agg(jsonb_build_object('name',c.name,'uid',c.uid,'gid',c.gid,'shell',c.shell) ORDER BY c.name),'[]'::jsonb) AS items
    FROM identity_local_accounts c WHERE c.event_id=i.event_id) d
   WHERE i.event_id=$1 AND (u.role='admin' OR (
    EXISTS(SELECT 1 FROM group_members m WHERE m.user_id=u.id AND m.group_id=i.group_id AND m.role IN ('viewer','analyst','admin')) AND
    EXISTS(SELECT 1 FROM group_members m WHERE m.user_id=u.id AND m.group_id=a.group_id AND m.role IN ('viewer','analyst','admin'))))`, id, u.ID).Scan(
			&result.EventID, &result.AssetID, &result.GroupID, &result.Ts, &result.State, &result.Source, &result.AccountCount, &result.Items)
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "本地账号快照读取失败", http.StatusInternalServerError)
			return
		}
		writeJSON(w, result)
	})
	return mux
}
