package api

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/identity/directory"
)

// 所有目录读取使用数据库当前角色/成员关系，不采信会话中缓存的管理员身份。
const directoryScope = ` JOIN users u ON u.id=$1 WHERE (u.role='admin' OR EXISTS(
 SELECT 1 FROM group_members m WHERE m.user_id=u.id AND m.group_id=s.group_id AND m.role IN ('viewer','analyst','admin')))`

type directorySource struct {
	ID               uuid.UUID  `json:"id"`
	GroupID          uuid.UUID  `json:"groupId"`
	Kind             string     `json:"kind"`
	Authority        string     `json:"authority"`
	LastStartedAt    *time.Time `json:"lastStartedAt"`
	LastFinishedAt   *time.Time `json:"lastFinishedAt"`
	LatestRunID      *uuid.UUID `json:"latestRunId"`
	LatestStatus     *string    `json:"latestStatus"`
	LatestErrorCode  *string    `json:"latestErrorCode"`
	LatestStartedAt  *time.Time `json:"latestStartedAt"`
	LatestFinishedAt *time.Time `json:"latestFinishedAt"`
}

type directoryAccount struct {
	WindowsSID *string   `json:"windowsSid"`
	ID         uuid.UUID `json:"id"`
	SourceID   uuid.UUID `json:"sourceId"`
	ExternalID string    `json:"externalId"`
	Username   string    `json:"username"`
	Enabled    *bool     `json:"enabled"`
	ObservedAt time.Time `json:"observedAt"`
}

func IdentityDirectories(db *sql.DB) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/identity-directories", func(w http.ResponseWriter, r *http.Request) {
		user, group, limit, ok := directoryParams(w, r, r.URL.Query().Get("groupId"))
		if !ok {
			return
		}
		rows, err := db.QueryContext(r.Context(), `SELECT s.id,s.group_id,s.kind,s.authority,s.last_started_at,s.last_finished_at,
 latest.id,latest.status,latest.error_code,latest.started_at,latest.finished_at FROM identity_directory_sources s
 LEFT JOIN LATERAL (SELECT id,status,error_code,started_at,finished_at FROM identity_directory_runs WHERE source_id=s.id ORDER BY started_at DESC,id DESC LIMIT 1) latest ON true`+
			directoryScope+` AND s.group_id=$2 ORDER BY s.id LIMIT $3`, user, group, limit+1)
		if err != nil {
			http.Error(w, "读取目录来源失败", 500)
			return
		}
		defer rows.Close()
		items := make([]directorySource, 0)
		for rows.Next() {
			var item directorySource
			if err := rows.Scan(&item.ID, &item.GroupID, &item.Kind, &item.Authority, &item.LastStartedAt, &item.LastFinishedAt, &item.LatestRunID, &item.LatestStatus, &item.LatestErrorCode, &item.LatestStartedAt, &item.LatestFinishedAt); err != nil {
				http.Error(w, "读取目录来源失败", 500)
				return
			}
			items = append(items, item)
		}
		if rows.Err() != nil {
			http.Error(w, "读取目录来源失败", 500)
			return
		}
		writeDirectoryItems(w, items, limit)
	})
	mux.HandleFunc("GET /api/identity-directories/{sourceId}/accounts", func(w http.ResponseWriter, r *http.Request) {
		user, source, limit, ok := directoryParams(w, r, r.PathValue("sourceId"))
		if !ok {
			return
		}
		after := uuid.Nil
		if value := r.URL.Query().Get("after"); value != "" {
			var err error
			after, err = uuid.Parse(value)
			if err != nil {
				http.Error(w, "after 无效", 400)
				return
			}
		}
		rows, err := db.QueryContext(r.Context(), `SELECT a.id,a.source_id,a.external_id,a.username,a.enabled,a.observed_at,a.windows_sid
 FROM identity_directory_accounts a JOIN identity_directory_sources s ON s.id=a.source_id`+directoryScope+
			` AND s.id=$2 AND a.id>$3 ORDER BY a.id LIMIT $4`, user, source, after, limit+1)
		if err != nil {
			http.Error(w, "读取目录账号失败", 500)
			return
		}
		defer rows.Close()
		items := make([]directoryAccount, 0)
		for rows.Next() {
			var item directoryAccount
			if err := rows.Scan(&item.ID, &item.SourceID, &item.ExternalID, &item.Username, &item.Enabled, &item.ObservedAt, &item.WindowsSID); err != nil {
				http.Error(w, "读取目录账号失败", 500)
				return
			}
			items = append(items, item)
		}
		if rows.Err() != nil {
			http.Error(w, "读取目录账号失败", 500)
			return
		}
		truncated := len(items) > limit
		if truncated {
			items = items[:limit]
		}
		var next *uuid.UUID
		if truncated {
			id := items[len(items)-1].ID
			next = &id
		}
		writeJSON(w, struct {
			Items     []directoryAccount `json:"items"`
			Truncated bool               `json:"truncated"`
			Next      *uuid.UUID         `json:"next"`
		}{items, truncated, next})
	})
	mux.HandleFunc("GET /api/identity-directories/{sourceId}/runs", func(w http.ResponseWriter, r *http.Request) {
		user, source, limit, ok := directoryParams(w, r, r.PathValue("sourceId"))
		if !ok {
			return
		}
		rows, err := db.QueryContext(r.Context(), `SELECT run.id,run.source_id,run.started_at,run.finished_at,run.status,run.error_code,run.account_count
 FROM identity_directory_runs run JOIN identity_directory_sources s ON s.id=run.source_id`+directoryScope+
			` AND s.id=$2 ORDER BY run.started_at DESC,run.id DESC LIMIT $3`, user, source, limit+1)
		if err != nil {
			http.Error(w, "读取目录运行记录失败", 500)
			return
		}
		defer rows.Close()
		items := make([]directory.Run, 0)
		for rows.Next() {
			var item directory.Run
			if err := rows.Scan(&item.ID, &item.SourceID, &item.StartedAt, &item.FinishedAt, &item.Status, &item.ErrorCode, &item.AccountCount); err != nil {
				http.Error(w, "读取目录运行记录失败", 500)
				return
			}
			items = append(items, item)
		}
		if rows.Err() != nil {
			http.Error(w, "读取目录运行记录失败", 500)
			return
		}
		writeDirectoryItems(w, items, limit)
	})
	return mux
}

func directoryParams(w http.ResponseWriter, r *http.Request, value string) (uuid.UUID, uuid.UUID, int, bool) {
	u := auth.From(r.Context())
	if u == nil {
		http.Error(w, "请先登录", 401)
		return uuid.Nil, uuid.Nil, 0, false
	}
	id, err := uuid.Parse(value)
	if err != nil || id == uuid.Nil {
		http.Error(w, "目录来源或组 ID 无效", 400)
		return uuid.Nil, uuid.Nil, 0, false
	}
	limit := 100
	if value := r.URL.Query().Get("limit"); value != "" {
		limit, err = strconv.Atoi(value)
		if err != nil || limit < 1 || limit > 200 {
			http.Error(w, "limit 必须为 1 到 200", 400)
			return uuid.Nil, uuid.Nil, 0, false
		}
	}
	return u.ID, id, limit, true
}

func writeDirectoryItems[T any](w http.ResponseWriter, items []T, limit int) {
	truncated := len(items) > limit
	if truncated {
		items = items[:limit]
	}
	writeJSON(w, struct {
		Items     []T  `json:"items"`
		Truncated bool `json:"truncated"`
	}{items, truncated})
}
