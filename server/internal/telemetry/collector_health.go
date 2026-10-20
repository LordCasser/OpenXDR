package telemetry

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// collectorHealthQuery 与采集健康通知同一口径（见 liveness.sweepHealth）：在线（未失联）、
// 快照 5 分钟内更新过的主机，按能力、状态、是否活性检测判定的静默（带原因）分组计数
const collectorHealthQuery = `
SELECT c.key, c.value->>'state', COALESCE(c.value->>'reason', '') <> '', count(*)
FROM assets a, jsonb_each(a.collector_health->'capabilities') c
WHERE a.agent_id IS NOT NULL AND a.silent_since IS NULL
  AND jsonb_typeof(a.collector_health->'capabilities') = 'object'
  AND (a.collector_health->>'receivedAt')::timestamptz > now() - interval '5 minutes'
  AND c.value->>'state' IN ('degraded', 'unavailable')
GROUP BY 1, 2, 3`

// collectorHealth 采集降级的主机数，抓取时现查：健康巡视只在 leader 上跑，指标若由巡视设置，
// 换过 leader 的节点会一直报旧值；现查让每个节点报的都是数据库里的同一份
type collectorHealth struct {
	db   *sql.DB
	desc *prometheus.Desc
}

// NewCollectorHealth 暴露 openxdr_collector_capability_problem_hosts{capability,state,silent}
func NewCollectorHealth(db *sql.DB) prometheus.Collector {
	return &collectorHealth{db: db, desc: prometheus.NewDesc(
		"openxdr_collector_capability_problem_hosts",
		"采集能力降级或不可用的在线主机数；silent=true 表示通道开着却持续收不到事件（agent 活性检测判定）",
		[]string{"capability", "state", "silent"}, nil,
	)}
}

func (c *collectorHealth) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *collectorHealth) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := c.db.QueryContext(ctx, collectorHealthQuery)
	if err != nil {
		// 不让整个 /metrics 失败：其余指标照常，日志里留痕
		slog.Warn("采集健康指标查询失败", "err", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var name, state string
		var silent bool
		var count float64
		if err := rows.Scan(&name, &state, &silent, &count); err != nil {
			slog.Warn("采集健康指标读取失败", "err", err)
			return
		}
		silentLabel := "false"
		if silent {
			silentLabel = "true"
		}
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, count, name, state, silentLabel)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("采集健康指标读取失败", "err", err)
	}
}
