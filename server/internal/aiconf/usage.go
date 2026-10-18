package aiconf

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
)

// Recorder 平台自己发起的模型调用记一行用量。写失败只记日志，不影响调用方
func Recorder(db *ent.Client, feature string) func(model string, input, output int) {
	return func(model string, input, output int) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := db.AIUsage.Create().SetFeature(feature).SetModel(model).SetInput(input).SetOutput(output).Exec(ctx); err != nil {
			slog.Warn("记录 AI 用量失败", "feature", feature, "err", err)
		}
	}
}

// UsageRow 按天、用途、模型聚合的一格。用途：chat AI 助手 / task 定时任务 / triage 事件研判 / annotate 资产标注 / explain 日志解读
type UsageRow struct {
	Day       string `json:"day"`
	Feature   string `json:"feature"`
	Model     string `json:"model"`
	Input     int64  `json:"input"`
	Output    int64  `json:"output"`
	CacheRead int64  `json:"cacheRead"`
	Calls     int64  `json:"calls"`
}

// TopSession 用量最多的会话
type TopSession struct {
	ID     uuid.UUID `json:"id"`
	Title  string    `json:"title"`
	Kind   string    `json:"kind"`
	Group  string    `json:"group"`
	Model  string    `json:"model"`
	Tokens int64     `json:"tokens"`
	Calls  int64     `json:"calls"`
	LastAt time.Time `json:"lastAt"`
}

type Overview struct {
	Rows []UsageRow   `json:"rows"`
	Top  []TopSession `json:"top"`
}

// 会话消息里 Pi 记的用量：每条助手消息一次模型调用
const piRows = `
SELECT to_char(m.created_at AT TIME ZONE $2, 'YYYY-MM-DD'), s.kind, COALESCE(NULLIF(m.content->>'model', ''), s.model),
  SUM(COALESCE((m.content->'usage'->>'input')::bigint, 0)), SUM(COALESCE((m.content->'usage'->>'output')::bigint, 0)),
  SUM(COALESCE((m.content->'usage'->>'cacheRead')::bigint, 0)), COUNT(*)
FROM session_messages m JOIN agent_sessions s ON s.id = m.session_id
WHERE m.role = 'assistant' AND m.created_at > now() - make_interval(days => $1) AND m.content ? 'usage'
GROUP BY 1, 2, 3`

const platformRows = `
SELECT to_char(ts AT TIME ZONE $2, 'YYYY-MM-DD'), feature, model, SUM(input), SUM(output), 0, COUNT(*)
FROM ai_usages WHERE ts > now() - make_interval(days => $1)
GROUP BY 1, 2, 3`

const topSessions = `
SELECT s.id, COALESCE(s.title, ''), s.kind, COALESCE(g.name, ''), s.model,
  SUM(COALESCE((m.content->'usage'->>'input')::bigint, 0) + COALESCE((m.content->'usage'->>'output')::bigint, 0)), COUNT(*), MAX(m.created_at)
FROM session_messages m JOIN agent_sessions s ON s.id = m.session_id LEFT JOIN groups g ON g.id = s.group_id
WHERE m.role = 'assistant' AND m.created_at > now() - make_interval(days => $1) AND m.content ? 'usage'
GROUP BY s.id, g.name ORDER BY 6 DESC LIMIT 10`

// Usage 最近 days 天的用量，按 tz 时区分天
func Usage(ctx context.Context, db *sql.DB, days int, tz string) (Overview, error) {
	out := Overview{Rows: []UsageRow{}, Top: []TopSession{}}
	for _, q := range []string{piRows, platformRows} {
		rows, err := db.QueryContext(ctx, q, days, tz)
		if err != nil {
			return out, err
		}
		for rows.Next() {
			var r UsageRow
			if err := rows.Scan(&r.Day, &r.Feature, &r.Model, &r.Input, &r.Output, &r.CacheRead, &r.Calls); err != nil {
				rows.Close()
				return out, err
			}
			out.Rows = append(out.Rows, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return out, err
		}
	}
	rows, err := db.QueryContext(ctx, topSessions, days)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var t TopSession
		if err := rows.Scan(&t.ID, &t.Title, &t.Kind, &t.Group, &t.Model, &t.Tokens, &t.Calls, &t.LastAt); err != nil {
			return out, err
		}
		out.Top = append(out.Top, t)
	}
	return out, rows.Err()
}
