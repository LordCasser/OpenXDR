package directory

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

var ErrSyncFailed = errors.New("目录同步失败，请查看同步错误分类")
var ErrSyncState = errors.New("目录同步状态未能确认")

type Run struct {
	ID           uuid.UUID  `json:"id"`
	SourceID     uuid.UUID  `json:"sourceId"`
	StartedAt    time.Time  `json:"startedAt"`
	FinishedAt   *time.Time `json:"finishedAt"`
	Status       string     `json:"status"`
	ErrorCode    string     `json:"errorCode"`
	AccountCount int        `json:"accountCount"`
}

// SyncOnce 由可信配置/调度入口调用。只有事先登记且绑定一致的来源可以发起读取。
// 读失败保留旧账号，成功时账号、成功游标和本次运行状态在同一事务提交。
// 并发允许只读枚举，由 SaveScan 的来源锁和版本检查拒绝迟到覆盖。
func SyncOnce(ctx context.Context, db *sql.DB, source Source, reader Reader) (Run, error) {
	ctx, stop := context.WithTimeout(ctx, 3*time.Minute)
	defer stop()
	if err := source.validate(); err != nil {
		return Run{}, err
	}
	if reader == nil {
		return Run{}, ErrSyncFailed
	}
	run := Run{ID: uuid.New(), SourceID: source.ID, Status: "running"}
	err := db.QueryRowContext(ctx, `INSERT INTO identity_directory_runs(id,source_id,status)
SELECT $1,id,'running' FROM identity_directory_sources WHERE id=$2 AND group_id=$3 AND kind=$4 AND authority=$5
RETURNING started_at`, run.ID, source.ID, source.GroupID, source.Kind, source.Authority).Scan(&run.StartedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, ErrSourceConflict
	}
	if err != nil {
		return Run{}, ErrSyncState
	}
	readCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	scan, readErr := reader.ReadAccounts(readCtx)
	contextErr := readCtx.Err()
	cancel()
	code := ""
	switch {
	case contextErr != nil:
		code = "canceled"
	case readErr != nil:
		code = "read_failed"
	case scan.Source != source:
		code = "source_mismatch"
	case scan.validate() != nil:
		code = "invalid_result"
	}
	if code != "" {
		return failRun(db, run, code)
	}
	if err := finishRun(ctx, db, run.ID, scan); err != nil {
		code = "persist_failed"
		if errors.Is(err, ErrStaleScan) {
			code = "stale_scan"
		}
		return failRun(db, run, code)
	}
	// 重新读取已提交状态；提交结果未知时不能擅自把成功记录改成失败。
	stored, err := readRun(ctx, db, run.ID)
	if err != nil {
		return run, ErrSyncState
	}
	return stored, nil
}

func finishRun(ctx context.Context, db *sql.DB, id uuid.UUID, scan Scan) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := saveScanTx(ctx, tx, scan); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE identity_directory_runs SET status='succeeded',finished_at=clock_timestamp(),account_count=$2
WHERE id=$1 AND status='running' AND started_at>clock_timestamp()-interval '5 minutes'`, id, len(scan.Accounts))
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return ErrSyncState
	}
	return tx.Commit()
}

func failRun(db *sql.DB, run Run, code string) (Run, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctx, `UPDATE identity_directory_runs SET status='failed',error_code=$2,finished_at=clock_timestamp()
WHERE id=$1 AND status='running'`, run.ID, code)
	if err != nil {
		return run, ErrSyncState
	}
	stored, err := readRun(ctx, db, run.ID)
	if err != nil {
		return run, ErrSyncState
	}
	if stored.Status == "succeeded" {
		return stored, nil
	}
	return stored, ErrSyncFailed
}

func readRun(ctx context.Context, db *sql.DB, id uuid.UUID) (Run, error) {
	var run Run
	err := db.QueryRowContext(ctx, `SELECT id,source_id,started_at,finished_at,status,error_code,account_count FROM identity_directory_runs WHERE id=$1`, id).
		Scan(&run.ID, &run.SourceID, &run.StartedAt, &run.FinishedAt, &run.Status, &run.ErrorCode, &run.AccountCount)
	if err != nil {
		return Run{}, ErrSyncState
	}
	return run, nil
}
