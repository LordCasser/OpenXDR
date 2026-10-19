package api

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/auth"
)

type localIdentityCandidate struct {
	EventID    uuid.UUID `json:"eventId"`
	ObservedAt time.Time `json:"observedAt"`
	Name       string    `json:"name"`
	UID        int64     `json:"uid"`
	GID        int64     `json:"gid"`
	Shell      string    `json:"shell"`
}

// localIdentityCandidates 返回登录前 24 小时同设备同组的历史同名观察，不建立身份等价边。
func localIdentityCandidates(db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := auth.From(r.Context())
		if u == nil {
			http.Error(w, "请先登录", 401)
			return
		}
		id, err := uuid.Parse(r.PathValue("eventId"))
		if err != nil || id == uuid.Nil {
			http.Error(w, "eventId 无效", 400)
			return
		}
		rows, err := db.QueryContext(r.Context(), `SELECT c.event_id,c.ts,c.name,c.uid,c.gid,c.shell
 FROM identity_observations i JOIN events login ON login.id=i.event_id
 JOIN assets asset ON asset.id=i.asset_id JOIN users u ON u.id=$1
 LEFT JOIN LATERAL (
  SELECT s.event_id,e.ts,a.name,a.uid,a.gid,a.shell
  FROM identity_local_snapshots s JOIN events e ON e.id=s.event_id JOIN identity_local_accounts a ON a.event_id=s.event_id
  WHERE i.state='missing_uid' AND s.asset_id=i.asset_id AND s.group_id=i.group_id AND s.state='observed'
   AND a.name=i.account_name AND e.ts<=login.ts AND e.ts>=login.ts-interval '24 hours'
  ORDER BY e.ts DESC,s.event_id DESC LIMIT 21
 ) c ON true
 WHERE i.event_id=$2 AND (u.role='admin' OR (
  EXISTS(SELECT 1 FROM group_members m WHERE m.user_id=u.id AND m.group_id=i.group_id AND m.role IN ('viewer','analyst','admin')) AND
  EXISTS(SELECT 1 FROM group_members m WHERE m.user_id=u.id AND m.group_id=asset.group_id AND m.role IN ('viewer','analyst','admin'))))
 ORDER BY c.ts DESC,c.event_id DESC`, u.ID, id)
		if err != nil {
			http.Error(w, "本地账号候选查询失败", 500)
			return
		}
		defer rows.Close()
		items := make([]localIdentityCandidate, 0)
		visible := false
		for rows.Next() {
			visible = true
			var event uuid.NullUUID
			var ts sql.NullTime
			var name, shell sql.NullString
			var uid, gid sql.NullInt64
			if err := rows.Scan(&event, &ts, &name, &uid, &gid, &shell); err != nil {
				http.Error(w, "本地账号候选读取失败", 500)
				return
			}
			if event.Valid {
				items = append(items, localIdentityCandidate{event.UUID, ts.Time, name.String, uid.Int64, gid.Int64, shell.String})
			}
		}
		if rows.Err() != nil {
			http.Error(w, "本地账号候选读取失败", 500)
			return
		}
		if !visible {
			http.NotFound(w, r)
			return
		}
		truncated := len(items) > 20
		if truncated {
			items = items[:20]
		}
		writeJSON(w, struct {
			Items     []localIdentityCandidate `json:"items"`
			Truncated bool                     `json:"truncated"`
		}{items, truncated})
	})
}
