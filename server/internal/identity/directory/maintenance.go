package directory

import (
	"context"
	"database/sql"
	"log/slog"
	"time"
)

// MaintainRuns 只回收超过提交期限的运行记录，不能据此断言远端目录不可用。
// 每项最多处理 1000 条，跳过持锁行；终态清理至少保留每个来源最新一条记录。
func MaintainRuns(ctx context.Context, db *sql.DB, retention time.Duration) (expired, removed int64, err error) {
	result, err := db.ExecContext(ctx, `WITH expired AS (
 SELECT id FROM identity_directory_runs WHERE status='running' AND started_at<=clock_timestamp()-interval '5 minutes'
 ORDER BY started_at,id LIMIT 1000 FOR UPDATE SKIP LOCKED)
 UPDATE identity_directory_runs r SET status='failed',error_code='deadline_exceeded',finished_at=clock_timestamp()
 FROM expired WHERE r.id=expired.id`)
	if err != nil {
		return 0, 0, err
	}
	expired, err = result.RowsAffected()
	if err != nil || retention <= 0 {
		return expired, 0, err
	}
	result, err = db.ExecContext(ctx, `WITH old AS (
 SELECT r.id FROM identity_directory_runs r WHERE r.status IN ('succeeded','failed')
 AND r.finished_at<clock_timestamp()-($1::double precision * interval '1 second')
 AND EXISTS(SELECT 1 FROM identity_directory_runs newer WHERE newer.source_id=r.source_id
 AND (newer.started_at,newer.id)>(r.started_at,r.id))
 ORDER BY r.finished_at,r.id LIMIT 1000 FOR UPDATE OF r SKIP LOCKED)
 DELETE FROM identity_directory_runs r USING old WHERE r.id=old.id`, retention.Seconds())
	if err != nil {
		return expired, 0, err
	}
	removed, err = result.RowsAffected()
	return expired, removed, err
}

func RunMaintenance(ctx context.Context, db *sql.DB, retention time.Duration) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for ctx.Err() == nil {
		workCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		expired, removed, err := MaintainRuns(workCtx, db, retention)
		cancel()
		if err != nil {
			slog.Warn("目录运行记录维护未完成")
		} else if expired > 0 || removed > 0 {
			slog.Info("目录运行记录维护完成", "expired", expired, "removed", removed)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
