package temporal

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/google/uuid"
)

// EnsureSchema 创建可重启恢复的候选及命中证据。资产换组会清除候选，
// 即使先换到 B 再换回 A、期间没有事件，也不会复用旧 A 的序列状态。
func EnsureSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS temporal_rule_snapshots (
 revision text PRIMARY KEY, document jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS temporal_candidates (
 revision text NOT NULL, event_id uuid NOT NULL REFERENCES events(id) ON DELETE CASCADE,
 asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
 group_id uuid NOT NULL, ts timestamptz NOT NULL, rules jsonb NOT NULL,
 PRIMARY KEY(revision,event_id));
CREATE INDEX IF NOT EXISTS temporal_candidates_window ON temporal_candidates(revision,asset_id,group_id,ts);
CREATE TABLE IF NOT EXISTS temporal_evaluation_gaps (
 revision text NOT NULL, event_id uuid NOT NULL REFERENCES events(id) ON DELETE CASCADE,
 asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE, group_id uuid NOT NULL,
 reason text NOT NULL, candidate_count_lower_bound integer NOT NULL,
 window_from timestamptz NOT NULL, window_to timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(revision,event_id));
CREATE INDEX IF NOT EXISTS temporal_evaluation_gaps_scope ON temporal_evaluation_gaps(group_id,asset_id,created_at);
CREATE INDEX IF NOT EXISTS temporal_evaluation_gaps_asset ON temporal_evaluation_gaps(asset_id,created_at DESC,revision DESC,event_id DESC);
CREATE TABLE IF NOT EXISTS temporal_detections (
 revision text NOT NULL, rule_id text NOT NULL,
 anchor_id uuid NOT NULL REFERENCES events(id) ON DELETE CASCADE,
 group_id uuid NOT NULL, entity text NOT NULL, evidence jsonb NOT NULL,
 PRIMARY KEY(revision,rule_id,anchor_id));
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='temporal_detections'::regclass AND attname='alert_id' AND NOT attisdropped) THEN
 ALTER TABLE temporal_detections ADD COLUMN alert_id uuid REFERENCES alerts(id) ON DELETE CASCADE;
 END IF;
END $$;
CREATE INDEX IF NOT EXISTS temporal_candidates_event ON temporal_candidates(event_id);
CREATE INDEX IF NOT EXISTS temporal_evaluation_gaps_event ON temporal_evaluation_gaps(event_id);
CREATE INDEX IF NOT EXISTS temporal_detections_anchor ON temporal_detections(anchor_id);
CREATE TABLE IF NOT EXISTS temporal_evidence (
 revision text NOT NULL, rule_id text NOT NULL, anchor_id uuid NOT NULL,
 event_id uuid NOT NULL REFERENCES events(id) ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
 PRIMARY KEY(revision,rule_id,anchor_id,event_id),
 FOREIGN KEY(revision,rule_id,anchor_id) REFERENCES temporal_detections(revision,rule_id,anchor_id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS temporal_evidence_event ON temporal_evidence(event_id);
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='temporal_candidates_revision_fk' AND conrelid='temporal_candidates'::regclass) THEN
 ALTER TABLE temporal_candidates ADD CONSTRAINT temporal_candidates_revision_fk FOREIGN KEY(revision) REFERENCES temporal_rule_snapshots(revision) ON DELETE RESTRICT NOT VALID;
 END IF;
END $$;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='temporal_detections_revision_fk' AND conrelid='temporal_detections'::regclass) THEN
 ALTER TABLE temporal_detections ADD CONSTRAINT temporal_detections_revision_fk FOREIGN KEY(revision) REFERENCES temporal_rule_snapshots(revision) ON DELETE RESTRICT NOT VALID;
 END IF;
END $$;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='temporal_evaluation_gaps_revision_fk' AND conrelid='temporal_evaluation_gaps'::regclass) THEN
 ALTER TABLE temporal_evaluation_gaps ADD CONSTRAINT temporal_evaluation_gaps_revision_fk FOREIGN KEY(revision) REFERENCES temporal_rule_snapshots(revision) ON DELETE RESTRICT NOT VALID;
 END IF;
END $$;
CREATE OR REPLACE FUNCTION openxdr_reset_temporal_scope() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.group_id IS DISTINCT FROM NEW.group_id THEN
  DELETE FROM temporal_candidates WHERE asset_id=NEW.id;
 END IF;
 RETURN NEW;
END $$;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='openxdr_temporal_scope' AND tgrelid='assets'::regclass) THEN
 CREATE TRIGGER openxdr_temporal_scope AFTER UPDATE OF group_id ON assets
 FOR EACH ROW EXECUTE FUNCTION openxdr_reset_temporal_scope();
 END IF;
END $$;`)
	return err
}

type Observation struct {
	Unscoped         bool
	CapacityExceeded bool
	Matches          []Match
}

// Observe 必须在事件与告警共用的事务中调用。基础命中只能来自该 snapshot。
// 组和资产从数据库获取；没有分组时显式返回 Unscoped，不使用自报归属。
// 当前实体维度为单资产；跨资产/用户聚合须另定义实体契约。
func (s *Snapshot) Observe(ctx context.Context, tx *sql.Tx, id uuid.UUID, ruleIDs []string) (Observation, error) {
	var e Event
	var assetID, groupID uuid.NullUUID
	err := tx.QueryRowContext(ctx, `SELECT e.id,e.ts,e.asset_id,a.group_id FROM events e
 LEFT JOIN assets a ON a.id=e.asset_id WHERE e.id=$1`, id).Scan(&e.ID, &e.Time, &assetID, &groupID)
	if err != nil {
		return Observation{}, err
	}
	if !assetID.Valid {
		return Observation{Unscoped: true}, nil
	}
	// 锁住资产行再重新读组，避免归组查询与换组之间的竞态。
	if err := tx.QueryRowContext(ctx, `SELECT group_id FROM assets WHERE id=$1 FOR SHARE`, assetID.UUID).Scan(&groupID); err != nil {
		return Observation{}, err
	}
	if !groupID.Valid || groupID.UUID == uuid.Nil {
		return Observation{Unscoped: true}, nil
	}
	e.Scope = Scope{Group: groupID.UUID, Entity: assetID.UUID.String()}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "temporal|"+s.revision+"|"+e.Scope.Entity); err != nil {
		return Observation{}, err
	}
	if err := s.persistArchive(ctx, tx); err != nil {
		return Observation{}, err
	}
	e.Rules = append([]string(nil), ruleIDs...)
	slices.Sort(e.Rules)
	e.Rules = slices.Compact(e.Rules)
	known := map[string]bool{}
	for _, rule := range s.base.Rules() {
		known[rule.ID] = true
	}
	for _, id := range e.Rules {
		if !known[id] {
			return Observation{}, fmt.Errorf("未知快照基础命中: %s", id)
		}
	}
	encoded, err := json.Marshal(e.Rules)
	if err != nil {
		return Observation{}, err
	}
	var accepted uuid.UUID
	err = tx.QueryRowContext(ctx, `INSERT INTO temporal_candidates AS existing(revision,event_id,asset_id,group_id,ts,rules)
VALUES($1,$2,$3,$4,$5,$6::jsonb) ON CONFLICT(revision,event_id) DO UPDATE SET rules=existing.rules
WHERE existing.asset_id=EXCLUDED.asset_id AND existing.group_id=EXCLUDED.group_id
AND existing.ts=EXCLUDED.ts AND existing.rules=EXCLUDED.rules RETURNING event_id`,
		s.revision, e.ID, assetID.UUID, groupID.UUID, e.Time, string(encoded)).Scan(&accepted)
	if err != nil {
		return Observation{}, fmt.Errorf("时序候选写入失败或重投内容冲突: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT event_id,ts,rules FROM temporal_candidates
WHERE revision=$1 AND asset_id=$2 AND group_id=$3 AND ts >= $4 AND ts <= $5
ORDER BY ts,event_id LIMIT 10001`, s.revision, assetID.UUID, groupID.UUID, e.Time.Add(-s.window), e.Time.Add(s.window))
	if err != nil {
		return Observation{}, err
	}
	var candidates []Event
	for rows.Next() {
		candidate := Event{Scope: e.Scope}
		var data []byte
		if err := rows.Scan(&candidate.ID, &candidate.Time, &data); err != nil {
			rows.Close()
			return Observation{}, err
		}
		if err := json.Unmarshal(data, &candidate.Rules); err != nil {
			rows.Close()
			return Observation{}, err
		}
		candidates = append(candidates, candidate)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return Observation{}, err
	}
	if len(candidates) > 10000 {
		// 容量缺口与事件/基础告警一起提交，避免永久阻塞该资产所在的队列分片。
		// 不在截断窗口上求值，也不将重投视为自动补检。
		_, err := tx.ExecContext(ctx, `INSERT INTO temporal_evaluation_gaps
 (revision,event_id,asset_id,group_id,reason,candidate_count_lower_bound,window_from,window_to)
 VALUES($1,$2,$3,$4,'candidate_limit',$5,$6,$7) ON CONFLICT(revision,event_id) DO NOTHING`,
			s.revision, e.ID, assetID.UUID, groupID.UUID, len(candidates), e.Time.Add(-s.window), e.Time.Add(s.window))
		if err != nil {
			return Observation{}, err
		}
		return Observation{CapacityExceeded: true}, nil
	}
	matches, err := s.Evaluate(candidates)
	if err != nil {
		return Observation{}, err
	}
	var result Observation
	for _, match := range matches {
		// 新事件只可能改变它之后（含同一时刻）终点的结果；更早的终点已在当时求值落库
		if match.Time.Before(e.Time) {
			continue
		}
		evidence, err := json.Marshal(match.Evidence)
		if err != nil {
			return Observation{}, err
		}
		inserted, err := tx.ExecContext(ctx, `INSERT INTO temporal_detections(revision,rule_id,anchor_id,group_id,entity,evidence)
VALUES($1,$2,$3,$4,$5,$6::jsonb) ON CONFLICT DO NOTHING`, match.Revision, match.RuleID, match.Anchor, match.Scope.Group, match.Scope.Entity, string(evidence))
		if err != nil {
			return Observation{}, err
		}
		n, err := inserted.RowsAffected()
		if err != nil {
			return Observation{}, err
		}
		if n > 0 {
			for _, evidenceID := range match.Evidence {
				if evidenceID == match.Anchor {
					continue
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO temporal_evidence(revision,rule_id,anchor_id,event_id) VALUES($1,$2,$3,$4)`, match.Revision, match.RuleID, match.Anchor, evidenceID); err != nil {
					return Observation{}, err
				}
			}
			result.Matches = append(result.Matches, match)
		}
	}
	return result, nil
}
