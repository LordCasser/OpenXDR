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
	"openxdr/server/internal/temporal"
)

type temporalRuleVersion struct {
	Revision      string    `json:"revision"`
	CreatedAt     time.Time `json:"createdAt"`
	Format        int       `json:"format"`
	BaseRuleCount int       `json:"baseRuleCount"`
	TemporalRules []string  `json:"temporalRules"`
}

// TemporalRuleSnapshots 已归档的时序规则版本：列出最近版本、按版本哈希取原文与元数据。
// 规则原文属于检测配置，只有全局 admin / analyst 可读；角色每次从库里取，降权立即生效。
// alertId 只返回调用者能看到的告警所绑定的版本，看不到的告警按不存在处理。
func TemporalRuleSnapshots(db *sql.DB) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/temporal-rule-snapshots", func(w http.ResponseWriter, r *http.Request) {
		u, ok := temporalRuleReader(w, r, db)
		if !ok {
			return
		}
		p := r.URL.Query()
		limit := 20
		if value := p.Get("limit"); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > 100 {
				http.Error(w, "limit 必须为 1 到 100", http.StatusBadRequest)
				return
			}
			limit = n
		}
		var alert uuid.NullUUID
		if value := p.Get("alertId"); value != "" {
			id, err := uuid.Parse(value)
			if err != nil || id == uuid.Nil {
				http.Error(w, "alertId 无效", http.StatusBadRequest)
				return
			}
			alert = uuid.NullUUID{UUID: id, Valid: true}
		}
		rows, err := db.QueryContext(r.Context(), `SELECT s.revision,s.created_at,COALESCE((s.document->>'format')::int,0),
 (SELECT count(*) FROM jsonb_object_keys(CASE WHEN jsonb_typeof(s.document->'base')='object' THEN s.document->'base' END)),
 (SELECT COALESCE(jsonb_agg(k ORDER BY k),'[]'::jsonb) FROM jsonb_object_keys(CASE WHEN jsonb_typeof(s.document->'temporal')='object' THEN s.document->'temporal' END) k)
 FROM temporal_rule_snapshots s JOIN users u ON u.id=$1
 WHERE $2::uuid IS NULL OR EXISTS(SELECT 1 FROM temporal_detections d JOIN alerts a ON a.id=d.alert_id LEFT JOIN assets x ON x.id=a.asset_id
  WHERE d.revision=s.revision AND d.alert_id=$2 AND (u.role='admin' OR EXISTS(SELECT 1 FROM group_members m WHERE m.user_id=u.id AND m.group_id=x.group_id)))
 ORDER BY s.created_at DESC,s.revision DESC LIMIT $3`, u, alert, limit+1)
		if err != nil {
			http.Error(w, "读取时序规则版本失败", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		items := make([]temporalRuleVersion, 0)
		for rows.Next() {
			var v temporalRuleVersion
			var ids []byte
			if err := rows.Scan(&v.Revision, &v.CreatedAt, &v.Format, &v.BaseRuleCount, &ids); err != nil || json.Unmarshal(ids, &v.TemporalRules) != nil {
				http.Error(w, "读取时序规则版本失败", http.StatusInternalServerError)
				return
			}
			items = append(items, v)
		}
		if rows.Err() != nil {
			http.Error(w, "读取时序规则版本失败", http.StatusInternalServerError)
			return
		}
		truncated := len(items) > limit
		if truncated {
			items = items[:limit]
		}
		writeJSON(w, struct {
			Items     []temporalRuleVersion `json:"items"`
			Truncated bool                  `json:"truncated"`
		}{items, truncated})
	})
	mux.HandleFunc("GET /api/temporal-rule-snapshots/{revision}", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := temporalRuleReader(w, r, db); !ok {
			return
		}
		revision := r.PathValue("revision")
		var created time.Time
		var document []byte
		err := db.QueryRowContext(r.Context(), `SELECT created_at,document FROM temporal_rule_snapshots WHERE revision=$1`, revision).Scan(&created, &document)
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "读取时序规则版本失败", http.StatusInternalServerError)
			return
		}
		rules, err := temporal.ViewArchive(document, revision)
		if err != nil {
			// 归档被改动或格式不支持时不展示，免得把不可信内容当成当时的规则
			http.Error(w, "规则归档校验失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if id := r.URL.Query().Get("rule"); id != "" {
			var picked []temporal.ArchivedRule
			for _, rule := range rules {
				if rule.ID == id {
					picked = append(picked, rule)
				}
			}
			if len(picked) == 0 {
				http.Error(w, "该版本没有这条时序规则", http.StatusNotFound)
				return
			}
			rules = picked
		}
		writeJSON(w, struct {
			Revision  string                  `json:"revision"`
			CreatedAt time.Time               `json:"createdAt"`
			Rules     []temporal.ArchivedRule `json:"rules"`
		}{revision, created, rules})
	})
	return mux
}

// temporalRuleReader 从库里取当前角色：只有 admin / analyst 能读规则原文。
func temporalRuleReader(w http.ResponseWriter, r *http.Request, db *sql.DB) (uuid.UUID, bool) {
	u := auth.From(r.Context())
	if u == nil {
		http.Error(w, "请先登录", http.StatusUnauthorized)
		return uuid.Nil, false
	}
	var role string
	if err := db.QueryRowContext(r.Context(), `SELECT role FROM users WHERE id=$1`, u.ID).Scan(&role); err != nil {
		http.Error(w, "读取用户角色失败", http.StatusInternalServerError)
		return uuid.Nil, false
	}
	if !auth.Allowed(role, "analyst") {
		http.Error(w, "当前角色无此权限", http.StatusForbidden)
		return uuid.Nil, false
	}
	return u.ID, true
}
