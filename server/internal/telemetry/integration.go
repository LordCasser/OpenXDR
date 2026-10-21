package telemetry

import (
	"context"
	"database/sql"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type integrationQueue struct {
	db                            *sql.DB
	deliveries, attempts, age, up *prometheus.Desc
}

func NewIntegrationQueue(db *sql.DB) prometheus.Collector {
	return &integrationQueue{
		db:         db,
		deliveries: prometheus.NewDesc("openxdr_integration_deliveries", "保留期内各状态的投递记录数，数据库全局快照", []string{"status"}, nil),
		attempts:   prometheus.NewDesc("openxdr_integration_attempts_retained", "保留期内各结果的投递尝试数，非永久累计值", []string{"result"}, nil),
		age:        prometheus.NewDesc("openxdr_integration_oldest_pending_seconds", "最老待发或在途记录的等待秒数", nil, nil),
		up:         prometheus.NewDesc("openxdr_integration_metrics_up", "集成队列指标查询是否成功", nil, nil),
	}
}
func (c *integrationQueue) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.deliveries
	ch <- c.attempts
	ch <- c.age
	ch <- c.up
}
func (c *integrationQueue) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ok := true
	for _, q := range []struct {
		query string
		desc  *prometheus.Desc
	}{
		{"SELECT status,count(*) FROM integration_deliveries GROUP BY status", c.deliveries},
		{"SELECT result,count(*) FROM integration_attempts GROUP BY result", c.attempts},
	} {
		rows, err := c.db.QueryContext(ctx, q.query)
		if err != nil {
			ok = false
			continue
		}
		for rows.Next() {
			var label string
			var n float64
			if err = rows.Scan(&label, &n); err != nil {
				ok = false
				break
			}
			ch <- prometheus.MustNewConstMetric(q.desc, prometheus.GaugeValue, n, label)
		}
		if rows.Err() != nil {
			ok = false
		}
		rows.Close()
	}
	var age float64
	if err := c.db.QueryRowContext(ctx, "SELECT coalesce(greatest(extract(epoch FROM now()-min(created_at)),0),0) FROM integration_deliveries WHERE status IN ('pending','sending')").Scan(&age); err != nil {
		ok = false
	} else {
		ch <- prometheus.MustNewConstMetric(c.age, prometheus.GaugeValue, age)
	}
	up := 0.0
	if ok {
		up = 1
	}
	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, up)
}
