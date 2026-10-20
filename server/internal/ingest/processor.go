package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/cmdorigin"
	"openxdr/server/internal/identity"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/temporal"
)

type Metrics interface {
	Processed(source string, duplicate bool, alerts int, elapsed time.Duration)
	Failed(stage string)
}

type Processor struct {
	DB          *sql.DB
	Temporal    *temporal.Store
	Rules       sigma.Catalog
	Suppress    *suppress.Store
	Intel       *intel.Store
	DedupWindow time.Duration
	Metrics     Metrics
}

// EnsureSchema 创建事务处理状态。temporal_matches 是已消费命中的持久记录，
// 不能在事件仍保留时清空，否则迟到回看可能重复生成告警。
// 指向事件的列都不建外键：分区表的唯一约束必须含 ts，删除级联由 eventpart 的触发器与分区退役负责。
func EnsureSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS alert_dedup_state (
  fingerprint text PRIMARY KEY,
  alert_id uuid NOT NULL,
  first_ts timestamptz NOT NULL,
  last_ts timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS alert_dedup_last_ts ON alert_dedup_state(last_ts);
CREATE TABLE IF NOT EXISTS temporal_matches (
 rule_id text NOT NULL,
 event_id uuid NOT NULL,
 PRIMARY KEY(rule_id,event_id)
);
CREATE INDEX IF NOT EXISTS temporal_matches_event ON temporal_matches(event_id);`)
	if err != nil {
		return err
	}
	if err := temporal.EnsureSchema(ctx, db); err != nil {
		return err
	}
	return identity.EnsureSchema(ctx, db)
}

func (p *Processor) Process(ctx context.Context, e Envelope) (err error) {
	started := time.Now()
	alerts := 0
	duplicate := false
	var temporalSkipped []string
	defer func() {
		if p.Metrics != nil {
			if err != nil {
				p.Metrics.Failed("process")
			} else {
				p.Metrics.Processed(e.Source, duplicate, alerts, time.Since(started))
				if metrics, ok := p.Metrics.(interface{ TemporalSkipped(string) }); ok {
					for _, reason := range temporalSkipped {
						metrics.TemporalSkipped(reason)
					}
				}
			}
		}
	}()
	if err = e.Validate(); err != nil {
		return err
	}

	var snapshot *temporal.Snapshot
	if p.Temporal != nil {
		snapshot = p.Temporal.Current()
		if snapshot == nil {
			return fmt.Errorf("时序规则已配置但没有有效快照")
		}
	}
	tx, err := p.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// 同一身份的认证写入先串行，避免并发失败和成功都看不到对方未提交的事件。
	if authEntity(e) {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
			"auth-sequence|"+e.AssetID.String()+"|"+e.Username); err != nil {
			return err
		}
	}
	// 不写冲突列：分区表主键是 (id, ts)，老表是 id。稳定 ID 由含时间戳的来源字段算出，同一 id 必是同一 ts，两者等价
	result, err := tx.ExecContext(ctx, `INSERT INTO events
  (id, ts, class_uid, source, asset_id, process_guid, parent_process_guid, username, conn_tuple, raw)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)
ON CONFLICT DO NOTHING`, e.ID, e.Timestamp, e.ClassUID, e.Source,
		nullUUID(e.AssetID), nullUUID(e.ProcessGUID), nullUUID(e.ParentProcessGUID),
		nullString(e.Username), nullString(e.ConnTuple), string(e.Raw))
	if err != nil {
		return fmt.Errorf("事件落库: %w", err)
	}
	inserted, _ := result.RowsAffected()
	if inserted == 0 {
		duplicate = true
		return tx.Commit()
	}

	if e.Source == "agent" && e.ClassUID == 3002 && e.AssetID != nil {
		if err := identity.ObserveWindows(ctx, tx, e.ID); err != nil {
			return err
		}
		if err := identity.ObserveLinuxLogin(ctx, tx, e.ID); err != nil {
			return err
		}
	}
	if e.Source == "agent" && e.ClassUID == 5001 && e.AssetID != nil {
		if err := identity.ObserveLinuxAccounts(ctx, tx, e.ID); err != nil {
			return err
		}
	}
	var raw map[string]any
	if json.Unmarshal(e.Raw, &raw) != nil {
		raw = map[string]any{}
	}
	sigma.WithActor(raw, e.Username)
	var baseHits []*sigma.Rule
	if snapshot != nil {
		baseHits = snapshot.EvaluateBase(e.ClassUID, e.AssetOS, raw)
	} else {
		baseHits = p.Rules.Evaluate(e.ClassUID, e.AssetOS, raw)
	}
	var observation temporal.Observation
	if snapshot != nil {
		ids := snapshot.CandidateRules(baseHits)
		if len(ids) > 0 {
			observation, err = snapshot.Observe(ctx, tx, e.ID, ids)
			if err != nil {
				return err
			}
			temporalSkipped = observation.Skipped
		}
	}
	hits := intel.Detections(baseHits, p.Intel.Match(raw, e.Timestamp))
	var command *uuid.UUID
	if len(hits) > 0 {
		if command, err = cmdorigin.Of(ctx, tx, raw, e.AssetID, e.Timestamp); err != nil {
			return err
		}
	}
	for _, hit := range hits {
		if p.Suppress.Suppressed(hit.RuleID, e.AssetID, raw, e.Timestamp) {
			continue
		}
		created, err := p.upsertAlert(ctx, tx, e, hit, command)
		if err != nil {
			return err
		}
		if created {
			alerts++
		}
	}
	n, err := p.authSequence(ctx, tx, e, authStatus(raw))
	if err != nil {
		return err
	}
	alerts += n
	for _, match := range observation.Matches {
		created, err := p.temporalAlert(ctx, tx, match)
		if err != nil {
			return err
		}
		if created {
			alerts++
		}
	}
	return tx.Commit()
}

func (p *Processor) upsertAlert(ctx context.Context, tx *sql.Tx, e Envelope, hit intel.Hit, command *uuid.UUID) (bool, error) {
	fingerprint := alertFingerprint(e, hit, command)
	// 同一指纹的所有集群节点在事务内串行，窗口判断与告警计数不会竞争。
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, fingerprint); err != nil {
		return false, err
	}
	var alertID uuid.UUID
	var first time.Time
	err := tx.QueryRowContext(ctx, `SELECT alert_id, first_ts FROM alert_dedup_state WHERE fingerprint=$1`, fingerprint).
		Scan(&alertID, &first)
	if err == nil && !e.Timestamp.Before(first) && e.Timestamp.Sub(first) < p.DedupWindow {
		if _, err := tx.ExecContext(ctx, `UPDATE alerts SET count=count+1, last_ts=GREATEST(COALESCE(last_ts,ts),$2) WHERE id=$1`, alertID, e.Timestamp); err != nil {
			return false, err
		}
		_, err = tx.ExecContext(ctx, `UPDATE alert_dedup_state SET last_ts=GREATEST(last_ts,$2) WHERE fingerprint=$1`, fingerprint, e.Timestamp)
		return false, err
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}

	alertID = uuid.Must(uuid.NewV7())
	if _, err := tx.ExecContext(ctx, `INSERT INTO alerts
  (id, ts, rule_id, severity, event_id, asset_id, count, last_ts, command_id)
VALUES ($1,$2,$3,$4,$5,$6,1,$2,$7)`, alertID, e.Timestamp, hit.RuleID, hit.Severity, e.ID, nullUUID(e.AssetID), nullUUID(command)); err != nil {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO alert_dedup_state(fingerprint,alert_id,first_ts,last_ts)
VALUES($1,$2,$3,$3) ON CONFLICT(fingerprint) DO UPDATE
SET alert_id=EXCLUDED.alert_id, first_ts=EXCLUDED.first_ts, last_ts=EXCLUDED.last_ts`, fingerprint, alertID, e.Timestamp)
	return true, err
}

func authStatus(raw map[string]any) int {
	v, _ := raw["status_id"].(float64)
	return int(v)
}

func nullUUID(id *uuid.UUID) any {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func nullString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func alertFingerprint(e Envelope, hit intel.Hit, command *uuid.UUID) string {
	fingerprint := hit.RuleID + "|" + e.PartitionKey + e.FingerprintSuffix
	if hit.RuleID == sigma.RuleBruteforceSuccess {
		fingerprint += "|" + e.Username
	}
	// 指令触发的告警单独去重：否则之后同规则的真实命中会被并进这条「已知来源」的告警里
	if command != nil {
		fingerprint += "|cmd:" + command.String()
	}
	return fingerprint
}
