package directory

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

func RegisterJobs(ctx context.Context, db *sql.DB, jobs []Job) error {
	for i, job := range jobs {
		if err := RegisterSource(ctx, db, job.Source); err != nil {
			return fmt.Errorf("目录配置第 %d 项登记失败，请检查归组和既有来源绑定", i+1)
		}
	}
	return nil
}

// RunWorker 由 cluster.RunLeader 托管；来源独立计时，共享四个并发槽。
// 本轮完成后等待完整周期，不因失败立即重试，也不堆积错过的触发。
func RunWorker(ctx context.Context, db *sql.DB, jobs []Job) {
	runJobs(ctx, jobs, func(ctx context.Context, job Job) {
		run, err := SyncOnce(ctx, db, job.Source, job.Reader)
		if err != nil {
			slog.Warn("目录同步未成功", "source_id", job.Source.ID, "run_id", run.ID, "status", run.Status, "error_code", run.ErrorCode)
			return
		}
		slog.Info("目录同步完成", "source_id", job.Source.ID, "run_id", run.ID, "accounts", run.AccountCount)
	})
}

func runJobs(ctx context.Context, jobs []Job, syncOne func(context.Context, Job)) {
	var wg sync.WaitGroup
	slots := make(chan struct{}, 4)
	for _, job := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				select {
				case <-ctx.Done():
					return
				case slots <- struct{}{}:
				}
				if ctx.Err() == nil {
					syncOne(ctx, job)
				}
				<-slots
				timer := time.NewTimer(job.Interval)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}()
	}
	wg.Wait()
}
