package directory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"openxdr/server/internal/identity/sid"
	"time"
)

var ErrSourceConflict = errors.New("目录来源绑定不一致")
var ErrStaleScan = errors.New("目录枚举早于已保存版本")

func EnsureSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS identity_directory_sources (
 id uuid PRIMARY KEY, group_id uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
 kind text NOT NULL, authority text NOT NULL,
 last_started_at timestamptz, last_finished_at timestamptz);
CREATE INDEX IF NOT EXISTS identity_directory_sources_group ON identity_directory_sources(group_id);
CREATE TABLE IF NOT EXISTS identity_directory_accounts (
 id uuid PRIMARY KEY, source_id uuid NOT NULL REFERENCES identity_directory_sources(id) ON DELETE CASCADE,
 external_id text NOT NULL, username text NOT NULL, enabled boolean,
 observed_at timestamptz NOT NULL, UNIQUE(source_id,external_id));
ALTER TABLE identity_directory_accounts ADD COLUMN IF NOT EXISTS windows_sid text;
CREATE INDEX IF NOT EXISTS identity_directory_accounts_sid ON identity_directory_accounts(windows_sid,source_id) WHERE windows_sid IS NOT NULL;
CREATE TABLE IF NOT EXISTS identity_directory_runs (
 id uuid PRIMARY KEY, source_id uuid NOT NULL REFERENCES identity_directory_sources(id) ON DELETE CASCADE,
 started_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz,
 status text NOT NULL CHECK(status IN ('running','succeeded','failed')),
 error_code text NOT NULL DEFAULT '', account_count integer NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS identity_directory_runs_source ON identity_directory_runs(source_id,started_at DESC);
CREATE INDEX IF NOT EXISTS identity_directory_runs_pending ON identity_directory_runs(started_at,id) WHERE status='running';
CREATE INDEX IF NOT EXISTS identity_directory_runs_finished ON identity_directory_runs(finished_at,id) WHERE status IN ('succeeded','failed');`)
	return err
}

// RegisterSource 仅供可信配置入口使用。同一来源 ID 不允许换组、换类型或更换权威地址。
// 来源记录无凭据，不能将令牌或绑定密码放入 Authority。
func RegisterSource(ctx context.Context, db *sql.DB, source Source) error {
	if err := source.validate(); err != nil {
		return err
	}
	var matched bool
	err := db.QueryRowContext(ctx, `INSERT INTO identity_directory_sources(id,group_id,kind,authority)
VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET id=EXCLUDED.id
RETURNING group_id=$2 AND kind=$3 AND authority=$4`, source.ID, source.GroupID, source.Kind, source.Authority).Scan(&matched)
	if err != nil {
		return err
	}
	if !matched {
		return ErrSourceConflict
	}
	return nil
}

// SaveScan 原子保存一次成功枚举。没有出现在本轮的账号保留旧 observed_at，绝不推断删除。
// 通过来源行锁和开始时间防止多节点迟到扫描覆盖较新的账号状态。
func SaveScan(ctx context.Context, db *sql.DB, scan Scan) error {
	if err := scan.validate(); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := saveScanTx(ctx, tx, scan); err != nil {
		return err
	}
	return tx.Commit()
}

func saveScanTx(ctx context.Context, tx *sql.Tx, scan Scan) error {
	scan.StartedAt = scan.StartedAt.UTC().Truncate(time.Microsecond)
	scan.FinishedAt = scan.FinishedAt.UTC().Truncate(time.Microsecond)
	var source Source
	var previous sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT id,group_id,kind,authority,last_started_at FROM identity_directory_sources WHERE id=$1 FOR UPDATE`, scan.Source.ID).
		Scan(&source.ID, &source.GroupID, &source.Kind, &source.Authority, &previous)
	if err != nil {
		return err
	}
	if source != scan.Source {
		return ErrSourceConflict
	}
	if previous.Valid && !scan.StartedAt.After(previous.Time) {
		return ErrStaleScan
	}
	for _, account := range scan.Accounts {
		id, _ := source.AccountID(account.ExternalID)
		_, err := tx.ExecContext(ctx, `INSERT INTO identity_directory_accounts(id,source_id,external_id,username,enabled,observed_at,windows_sid)
VALUES($1,$2,$3,$4,$5,$6,NULLIF($7,'')) ON CONFLICT(source_id,external_id) DO UPDATE
SET username=EXCLUDED.username,enabled=EXCLUDED.enabled,observed_at=EXCLUDED.observed_at,windows_sid=EXCLUDED.windows_sid`, id, source.ID, account.ExternalID, account.Username, account.Enabled, scan.FinishedAt, account.WindowsSID)
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE identity_directory_sources SET last_started_at=$2,last_finished_at=$3 WHERE id=$1`, source.ID, scan.StartedAt, scan.FinishedAt)
	return err
}

func (s Scan) validate() error {
	if err := s.Source.validate(); err != nil {
		return err
	}
	if s.StartedAt.IsZero() || s.FinishedAt.Before(s.StartedAt) || s.FinishedAt.After(time.Now().Add(5*time.Minute)) || len(s.Accounts) > 10000 || s.Accounts == nil {
		return fmt.Errorf("目录枚举时间、数量或结果无效")
	}
	seen := make(map[string]bool, len(s.Accounts))
	seenSID := make(map[string]bool)
	for _, account := range s.Accounts {
		if !validText(account.ExternalID, 1024) || !validText(account.Username, 1024) || seen[account.ExternalID] {
			return fmt.Errorf("目录账号字段无效或稳定标识重复")
		}
		seen[account.ExternalID] = true
		if account.WindowsSID != "" {
			value, err := sid.Canonical(account.WindowsSID)
			if s.Source.Kind != "ad" || err != nil || value == "" || value != account.WindowsSID || seenSID[value] {
				return fmt.Errorf("目录 SID 来源、格式或唯一性无效")
			}
			seenSID[value] = true
		}
	}
	return nil
}
