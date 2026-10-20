// Package janitor 数据保留：按期清理过期的原始事件。
//
// 策略：只删没有被告警或时序证据引用的事件。被引用的事件是 incident 的证据，
// 跟着 incident 的生命周期走，不能因为到期就抹掉。
// 存储膨胀的主体本来就是无人问津的原始遥测，删掉它们即可。
//
// events 是分区表时，过期的日分区整体退役（证据并进月归档分区，其余随分区删除），
// 逐行删除只剩归档与默认分区里的少量行（迟到事件、异常时间戳、引用已解除的证据）。
package janitor

import (
	"context"
	stdsql "database/sql"
	"entgo.io/ent/dialect/sql"
	"log/slog"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/decoyobservation"
	"openxdr/server/ent/event"
	"openxdr/server/ent/session"
	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/temporal"
)

// 单批删除量：太大容易长事务锁表，太小则清理跟不上写入
const batchSize = 10000

type Janitor struct {
	DB        *ent.Client
	SQL       *stdsql.DB
	Retention time.Duration
	Interval  time.Duration
}

func (j *Janitor) Run(ctx context.Context) {
	if j.Retention <= 0 {
		slog.Warn("事件保留策略未启用：RETENTION_DAYS 为 0，events 表会持续增长")
	}
	ticker := time.NewTicker(j.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if j.Retention > 0 && j.SQL != nil {
				if n, dropped, err := eventpart.Retire(ctx, j.SQL, retireCutoff(time.Now(), j.Retention)); err != nil {
					slog.Error("退役过期事件分区失败", "err", err)
				} else if n > 0 {
					slog.Info("退役过期事件分区", "partitions", n, "dropped", dropped)
				}
			}
			if j.Retention > 0 {
				deleted, err := j.sweep(ctx)
				if err != nil {
					slog.Error("清理过期事件失败", "err", err)
				} else if deleted > 0 {
					slog.Info("清理过期事件", "deleted", deleted)
				}
			}
			if j.Retention > 0 && j.SQL != nil {
				if n, err := temporal.PruneArchives(ctx, j.SQL, time.Now().Add(-j.Retention)); err != nil {
					slog.Error("清理无引用时序归档失败", "err", err)
				} else if n > 0 {
					slog.Info("清理无引用时序归档", "deleted", n)
				}
			}
			if j.Retention > 0 {
				if n, err := j.sweepDecoys(ctx); err != nil {
					slog.Error("清理过期诱饵观察失败", "err", err)
				} else if n > 0 {
					slog.Info("清理过期诱饵观察", "deleted", n)
				}
			}
			// 过期会话是纯垃圾：认证早已拒绝它们，行却一直躺在表里
			if n, err := j.DB.Session.Delete().
				Where(session.ExpiresAtLT(time.Now())).
				Exec(ctx); err != nil {
				slog.Error("清理过期会话失败", "err", err)
			} else if n > 0 {
				slog.Info("清理过期会话", "deleted", n)
			}
		}
	}
}

// retireGuard 是时序证据可能引用的最老事件年龄：最大窗口 24 小时加迟到余量，再留一小时处理耗时。
// 退役分区不经外键或触发器兜底，必须只退役不会再被新证据引用的日子。
const retireGuard = 24*time.Hour + temporal.LateGrace + time.Hour

func retireCutoff(now time.Time, retention time.Duration) time.Time {
	return now.Add(-max(retention, retireGuard))
}

func (j *Janitor) sweep(ctx context.Context) (int, error) {
	cutoff := time.Now().Add(-j.Retention)
	// 分区表上逐行删除只碰最老日分区之前（归档与默认分区），日分区留给整体退役，免得删出一片死元组
	if j.SQL != nil {
		oldest, ok, err := eventpart.OldestDaily(ctx, j.SQL)
		if err != nil {
			return 0, err
		}
		if ok && oldest.Before(cutoff) {
			cutoff = oldest
		}
	}
	total := 0
	for {
		ids, err := j.DB.Event.Query().
			Where(event.TsLT(cutoff), event.Not(event.HasAlerts()), withoutTemporalEvidence).
			Limit(batchSize).
			IDs(ctx)
		if err != nil || len(ids) == 0 {
			return total, err
		}
		n, err := j.DB.Event.Delete().Where(event.IDIn(ids...), event.TsLT(cutoff)).Exec(ctx)
		total += n
		if err != nil {
			return total, err
		}
		// 不足一批说明已清完，避免空转
		if len(ids) < batchSize {
			return total, nil
		}
		// 让出时间片，别把连接池和 CPU 占满
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// 时序前序事件不一定直接挂告警，仍属于告警证据。并发删除的最终保护：老表靠外键，分区表靠 openxdr_events_release 触发器。
func withoutTemporalEvidence(selector *sql.Selector) {
	detections := sql.Table("temporal_detections")
	selector.Where(sql.NotExists(sql.Select(detections.C("anchor_id")).From(detections).
		Where(sql.And(sql.ColumnsEQ(detections.C("anchor_id"), selector.C(event.FieldID)), sql.NotNull(detections.C("alert_id"))))))
	evidence := sql.Table("temporal_evidence")
	selector.Where(sql.NotExists(sql.Select(evidence.C("event_id")).From(evidence).
		Where(sql.ColumnsEQ(evidence.C("event_id"), selector.C(event.FieldID)))))
}

// 至少保留 48 小时，覆盖 24 小时运行令牌、去重和事件配额窗口；复核证据不清理。
func (j *Janitor) sweepDecoys(ctx context.Context) (int, error) {
	if j.Retention <= 0 {
		return 0, nil
	}
	retention := max(j.Retention, 48*time.Hour)
	cutoff := time.Now().Add(-retention)
	total := 0
	for {
		ids, err := j.DB.DecoyObservation.Query().Where(decoyobservation.ReceivedAtLT(cutoff), decoyobservation.IncidentIDIsNil()).Limit(batchSize).IDs(ctx)
		if err != nil || len(ids) == 0 {
			return total, err
		}
		// 删除时再次检查复核引用，避免查询与删除之间人工提交的证据被清掉。
		n, err := j.DB.DecoyObservation.Delete().Where(decoyobservation.IDIn(ids...), decoyobservation.ReceivedAtLT(cutoff), decoyobservation.IncidentIDIsNil()).Exec(ctx)
		total += n
		if err != nil || len(ids) < batchSize {
			return total, err
		}
	}
}
