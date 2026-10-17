package janitor

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/review"
)

// AutoClose 把 AI 判良性、级别低于高危、放了 Days 天没人处理的事件按误报结案，
// 免得待处理清单被噪声撑满。需人工复核的事件（review.Needed）永远不会被关掉。
type AutoClose struct {
	DB       *ent.Client
	Days     int
	Interval time.Duration
}

// Run 拿到租约先扫一次再按周期扫：只靠定时器的话，部署频繁时每次重启都把计时清零，永远轮不到。
func (a *AutoClose) Run(ctx context.Context) {
	ticker := time.NewTicker(a.Interval)
	defer ticker.Stop()
	for {
		if n, err := a.sweep(ctx); err != nil {
			slog.Error("良性事件自动结案失败", "err", err)
		} else if n > 0 {
			slog.Info("良性事件自动结案", "closed", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sweep 单条 UPDATE，条件里带着状态：多节点重复执行也只会关一次。
func (a *AutoClose) sweep(ctx context.Context) (int, error) {
	if a.Days <= 0 {
		return 0, nil
	}
	now := time.Now()
	note := fmt.Sprintf("AI 判良性、级别低于高危、%d 天无人处理，系统自动结案", a.Days)
	n, err := a.DB.Incident.Update().
		Where(review.StaleBenign(now.AddDate(0, 0, -a.Days))).
		SetStatus("false_positive").SetResolution(note).SetResolvedBy(review.ClosedBy).SetResolvedAt(now).
		Save(ctx)
	if err == nil && n > 0 {
		audit.System(ctx, a.DB, "incident_auto_closed", "", fmt.Sprintf("自动结案 %d 个事件（%d 天无人处理的低危良性事件）", n, a.Days))
	}
	return n, err
}
