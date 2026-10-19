package api

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/auth"
)

type temporalGap struct {
	Revision                 string    `json:"revision"`
	EventID                  uuid.UUID `json:"eventId"`
	AssetID                  uuid.UUID `json:"assetId"`
	GroupID                  uuid.UUID `json:"groupId"`
	Reason                   string    `json:"reason"`
	CandidateCountLowerBound int       `json:"candidateCountLowerBound"`
	WindowFrom               time.Time `json:"windowFrom"`
	WindowTo                 time.Time `json:"windowTo"`
	CreatedAt                time.Time `json:"createdAt"`
}

// TemporalGaps 返回未完成的时序求值记录，空列表不代表检测覆盖完整。
func TemporalGaps(db *sql.DB) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/temporal-gaps", func(w http.ResponseWriter, r *http.Request) {
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
		rows, err := db.QueryContext(r.Context(), `SELECT g.revision,g.event_id,g.asset_id,g.group_id,g.reason,g.candidate_count_lower_bound,g.window_from,g.window_to,g.created_at
 FROM temporal_evaluation_gaps g JOIN assets a ON a.id=g.asset_id JOIN users u ON u.id=$1
 WHERE g.asset_id=$2 AND g.created_at >= $3 AND g.created_at <= $4 AND (u.role='admin' OR (
 EXISTS(SELECT 1 FROM group_members m WHERE m.user_id=u.id AND m.group_id=g.group_id AND m.role IN ('viewer','analyst','admin')) AND
 EXISTS(SELECT 1 FROM group_members m WHERE m.user_id=u.id AND m.group_id=a.group_id AND m.role IN ('viewer','analyst','admin'))))
 ORDER BY g.created_at DESC,g.revision DESC,g.event_id DESC LIMIT $5`, u.ID, asset, from, to, limit+1)
		if err != nil {
			http.Error(w, "读取时序检测缺口失败", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		items := make([]temporalGap, 0)
		for rows.Next() {
			var gap temporalGap
			if err := rows.Scan(&gap.Revision, &gap.EventID, &gap.AssetID, &gap.GroupID, &gap.Reason, &gap.CandidateCountLowerBound, &gap.WindowFrom, &gap.WindowTo, &gap.CreatedAt); err != nil {
				http.Error(w, "读取时序检测缺口失败", http.StatusInternalServerError)
				return
			}
			items = append(items, gap)
		}
		if rows.Err() != nil {
			http.Error(w, "读取时序检测缺口失败", http.StatusInternalServerError)
			return
		}
		truncated := len(items) > limit
		if truncated {
			items = items[:limit]
		}
		writeJSON(w, struct {
			Items     []temporalGap `json:"items"`
			Truncated bool          `json:"truncated"`
		}{items, truncated})
	})
	return mux
}
