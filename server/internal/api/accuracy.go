package api

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"openxdr/server/internal/review"
)

// accuracyCounts 一组已结案事件里 AI 研判与人工结论的对照。
// 只有人写了理由的结案（reviewed）算独立判断；一键采纳 AI（adopted）与系统自动结案（auto）只计数，
// 它们的结论就是 AI 的结论，算进去只会把准确率抬高。
type accuracyCounts struct {
	Reviewed int `json:"reviewed"`
	// AI 判良性的里面，人最终认定属实的是漏判
	AIBenign int `json:"aiBenign"`
	Missed   int `json:"missed"`
	// AI 判可疑或恶意的里面，人最终认定误报的是误判
	AIAlarm    int `json:"aiAlarm"`
	FalseAlarm int `json:"falseAlarm"`
	Adopted    int `json:"adopted"`
	Auto       int `json:"auto"`
}

type accuracyRow struct {
	Key   string `json:"key"`
	Title string `json:"title,omitempty"`
	accuracyCounts
}

type accuracyCase struct {
	ID         string    `json:"id"`
	Title      string    `json:"title"`
	Verdict    string    `json:"verdict"`
	Model      string    `json:"model"`
	Status     string    `json:"status"`
	ResolvedBy string    `json:"resolvedBy"`
	ResolvedAt time.Time `json:"resolvedAt"`
}

// 研判结论有效、已结案的事件，按结案方式归类。一个事件可以带多条规则，按规则统计时每条规则各算一次。
// 早期版本结案不记时间和结案人：那时只有人能结案，算独立判断，时间退回事件创建时间
const accuracyBase = `WITH done AS (
 SELECT i.id, coalesce(i.title,'') AS title, i.status, coalesce(i.resolved_by,'') AS resolved_by, coalesce(i.resolved_at, i.created_at) AS resolved_at,
  i.ai_verdict->>'verdict' AS verdict, coalesce(i.ai_verdict->>'model','') AS model,
  CASE WHEN i.resolved_by = $2 THEN 'auto' WHEN i.resolution_source = 'external_integration' THEN 'external'
   WHEN i.resolution_source IS NOT NULL THEN 'adopted' ELSE 'reviewed' END AS kind
 FROM incidents i
 WHERE i.status IN ('closed','false_positive') AND coalesce(i.resolved_at, i.created_at) >= $1
  AND i.ai_verdict->>'verdict' IN ('malicious','suspicious','benign'))`

const accuracySums = `count(*) FILTER (WHERE kind='reviewed'),
 count(*) FILTER (WHERE kind='reviewed' AND verdict='benign'),
 count(*) FILTER (WHERE kind='reviewed' AND verdict='benign' AND status='closed'),
 count(*) FILTER (WHERE kind='reviewed' AND verdict<>'benign'),
 count(*) FILTER (WHERE kind='reviewed' AND verdict<>'benign' AND status='false_positive'),
 count(*) FILTER (WHERE kind='adopted'),
 count(*) FILTER (WHERE kind='auto')`

// AIAccuracy 拿人工结案衡量 AI 研判：总体、按研判模型、按规则，以及最近的漏判与误判案例（admin，挂在 /api/settings 下）
func AIAccuracy(sqlDB *sql.DB, rules interface{ TitleOf(id string) string }) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/settings/ai/accuracy", func(w http.ResponseWriter, r *http.Request) {
		days, err := strconv.Atoi(r.URL.Query().Get("days"))
		if err != nil || days < 1 || days > 365 {
			days = 90
		}
		since := time.Now().AddDate(0, 0, -days)
		ctx := r.Context()
		group := func(key, from string) ([]accuracyRow, error) {
			rows, err := sqlDB.QueryContext(ctx, accuracyBase+` SELECT `+key+`, `+accuracySums+` FROM `+from+` GROUP BY 1
 ORDER BY count(*) FILTER (WHERE kind='reviewed') DESC, count(*) DESC LIMIT 50`, since, review.ClosedBy)
			if err != nil {
				return nil, err
			}
			defer rows.Close()
			var out []accuracyRow
			for rows.Next() {
				var a accuracyRow
				c := &a.accuracyCounts
				if err := rows.Scan(&a.Key, &c.Reviewed, &c.AIBenign, &c.Missed, &c.AIAlarm, &c.FalseAlarm, &c.Adopted, &c.Auto); err != nil {
					return nil, err
				}
				out = append(out, a)
			}
			return out, rows.Err()
		}
		cases := func(where string) ([]accuracyCase, error) {
			rows, err := sqlDB.QueryContext(ctx, accuracyBase+` SELECT id, title, verdict, model, status, resolved_by, resolved_at
 FROM done WHERE kind='reviewed' AND `+where+` ORDER BY resolved_at DESC LIMIT 10`, since, review.ClosedBy)
			if err != nil {
				return nil, err
			}
			defer rows.Close()
			var out []accuracyCase
			for rows.Next() {
				var c accuracyCase
				if err := rows.Scan(&c.ID, &c.Title, &c.Verdict, &c.Model, &c.Status, &c.ResolvedBy, &c.ResolvedAt); err != nil {
					return nil, err
				}
				out = append(out, c)
			}
			return out, rows.Err()
		}

		total, err := group(`''`, `done`)
		byModel, err2 := group(`model`, `done`)
		byRule, err3 := group(`a.rule_id`, `done JOIN (SELECT DISTINCT incident_id, rule_id FROM alerts) a ON a.incident_id = done.id`)
		missed, err4 := cases(`verdict='benign' AND status='closed'`)
		falseAlarms, err5 := cases(`verdict<>'benign' AND status='false_positive'`)
		for _, e := range []error{err, err2, err3, err4, err5} {
			if e != nil {
				http.Error(w, e.Error(), http.StatusInternalServerError)
				return
			}
		}
		for i := range byRule {
			byRule[i].Title = rules.TitleOf(byRule[i].Key)
		}
		var sum accuracyCounts
		if len(total) > 0 {
			sum = total[0].accuracyCounts
		}
		writeJSON(w, map[string]any{
			"days": days, "total": sum, "byModel": byModel, "byRule": byRule,
			"missed": missed, "falseAlarms": falseAlarms,
		})
	})
	return mux
}
