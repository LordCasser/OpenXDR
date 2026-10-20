package eventpart

import (
	"context"
	"database/sql"
	"log/slog"
	"time"
)

// Maintainer 预建日分区，必须经 cluster.RunLeader 单活运行。events 还不是分区表（迁移前的老库）时什么都不做，
// 迁移切换后下一轮自动接手，不需要重启。
type Maintainer struct {
	DB       *sql.DB
	Interval time.Duration
}

func (m *Maintainer) Run(ctx context.Context) {
	ticker := time.NewTicker(m.Interval)
	defer ticker.Stop()
	for {
		m.once(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m *Maintainer) once(ctx context.Context) {
	ok, err := Partitioned(ctx, m.DB)
	if err != nil {
		slog.Error("读取事件表分区状态失败", "err", err)
		return
	}
	if !ok {
		return
	}
	n, err := EnsureDays(ctx, m.DB, Parent, Today(), PremakeDays)
	if err != nil {
		slog.Error("预建事件分区失败，新事件会暂落默认分区", "err", err)
	}
	if n > 0 {
		slog.Info("预建事件分区", "created", n)
	}
	var stray int64
	if err := m.DB.QueryRowContext(ctx, `SELECT count(*) FROM `+DefaultName+` WHERE ts >= now() - interval '1 day'`).Scan(&stray); err == nil && stray > 0 {
		slog.Warn("默认分区里有近一天写入的事件：采集端时钟异常或预建落后", "count", stray)
	}
}
