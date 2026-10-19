package api

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/auth"
)

type identityCandidate struct {
	AccountID          uuid.UUID  `json:"accountId"`
	SourceID           uuid.UUID  `json:"sourceId"`
	Authority          string     `json:"authority"`
	Username           string     `json:"username"`
	SID                string     `json:"sid"`
	Enabled            *bool      `json:"enabled"`
	ObservedAt         time.Time  `json:"observedAt"`
	LastSuccessfulSync *time.Time `json:"lastSuccessfulSync"`
	SeenInLatestSync   bool       `json:"seenInLatestSync"`
}

// IdentityCandidates 给出同一历史组中 SID 精确相等的目录观察，不做自动身份合并。
func IdentityCandidates(db *sql.DB) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/identity-observations/{eventId}/directory-accounts", func(w http.ResponseWriter, r *http.Request) {
		u := auth.From(r.Context())
		if u == nil {
			http.Error(w, "请先登录", 401)
			return
		}
		event, err := uuid.Parse(r.PathValue("eventId"))
		if err != nil || event == uuid.Nil {
			http.Error(w, "eventId 无效", 400)
			return
		}
		rows, err := db.QueryContext(r.Context(), `SELECT candidate.id,candidate.source_id,candidate.authority,candidate.username,
 candidate.windows_sid,candidate.enabled,candidate.observed_at,candidate.last_finished_at,
 candidate.observed_at=candidate.last_finished_at
 FROM identity_observations i JOIN assets asset ON asset.id=i.asset_id JOIN users u ON u.id=$1
 LEFT JOIN LATERAL (
 SELECT a.id,a.source_id,s.authority,a.username,a.windows_sid,a.enabled,a.observed_at,s.last_finished_at
 FROM identity_directory_accounts a JOIN identity_directory_sources s ON s.id=a.source_id
 WHERE s.group_id=i.group_id AND s.kind='ad' AND i.state='observed' AND a.windows_sid=i.account_sid
 ORDER BY s.id,a.id LIMIT 21) candidate ON true
 WHERE i.event_id=$2 AND (u.role='admin' OR (
 EXISTS(SELECT 1 FROM group_members m WHERE m.user_id=u.id AND m.group_id=i.group_id AND m.role IN ('viewer','analyst','admin')) AND
 EXISTS(SELECT 1 FROM group_members m WHERE m.user_id=u.id AND m.group_id=asset.group_id AND m.role IN ('viewer','analyst','admin'))))`, u.ID, event)
		if err != nil {
			http.Error(w, "目录关联候选查询失败", 500)
			return
		}
		defer rows.Close()
		items := make([]identityCandidate, 0)
		visible := false
		for rows.Next() {
			visible = true
			var account, source uuid.NullUUID
			var authority, name, sid sql.NullString
			var enabled, latest sql.NullBool
			var observed, finished sql.NullTime
			if err := rows.Scan(&account, &source, &authority, &name, &sid, &enabled, &observed, &finished, &latest); err != nil {
				http.Error(w, "目录关联候选读取失败", 500)
				return
			}
			if !account.Valid {
				continue
			}
			item := identityCandidate{AccountID: account.UUID, SourceID: source.UUID, Authority: authority.String, Username: name.String, SID: sid.String, ObservedAt: observed.Time, SeenInLatestSync: latest.Valid && latest.Bool}
			if enabled.Valid {
				value := enabled.Bool
				item.Enabled = &value
			}
			if finished.Valid {
				value := finished.Time
				item.LastSuccessfulSync = &value
			}
			items = append(items, item)
		}
		if rows.Err() != nil {
			http.Error(w, "目录关联候选读取失败", 500)
			return
		}
		if !visible {
			http.Error(w, "身份观察不存在或不可访问", 404)
			return
		}
		truncated := len(items) > 20
		if truncated {
			items = items[:20]
		}
		writeJSON(w, struct {
			Items     []identityCandidate `json:"items"`
			Truncated bool                `json:"truncated"`
			Ambiguous bool                `json:"ambiguous"`
		}{items, truncated, len(items) > 1})
	})
	mux.Handle("GET /api/identity-observations/{eventId}/local-accounts", localIdentityCandidates(db))
	return mux
}
