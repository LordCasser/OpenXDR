package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/cmdorigin"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
)

func authEntity(e Envelope) bool {
	return e.ClassUID == 3002 && e.AssetID != nil && *e.AssetID != uuid.Nil && e.Username != ""
}

// 失败迟到时回看其后十分钟内的成功事件；输出始终绑定成功事件而非触发回看的失败。
// 事件、命中占位、告警必须在同一事务内提交。调用者已获取同资产/用户的事务锁。
func (p *Processor) authSequence(ctx context.Context, tx *sql.Tx, e Envelope, status int) (int, error) {
	if !authEntity(e) || (status != 1 && status != 2) {
		return 0, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT s.id,s.ts,s.source,s.raw FROM events s
WHERE s.class_uid=3002 AND s.asset_id=$1 AND s.username=$2 AND s.raw->>'status_id'='1'
AND (($3=1 AND s.id=$4) OR ($3=2 AND s.ts>$5 AND s.ts<=$6))
AND NOT EXISTS (SELECT 1 FROM temporal_matches m WHERE m.rule_id=$7 AND m.event_id=s.id)
AND (SELECT count(*) FROM (SELECT 1 FROM events f
 WHERE f.class_uid=3002 AND f.asset_id=s.asset_id AND f.username=s.username
 AND f.raw->>'status_id'='2' AND f.ts>=s.ts-interval '10 minutes' AND f.ts<s.ts LIMIT 5) failures)>=5
ORDER BY s.ts,s.id`, *e.AssetID, e.Username, status, e.ID, e.Timestamp, e.Timestamp.Add(10*time.Minute), sigma.RuleBruteforceSuccess)
	if err != nil {
		return 0, fmt.Errorf("认证序列回查: %w", err)
	}
	var candidates []Envelope
	for rows.Next() {
		candidate := Envelope{Version: EnvelopeVersion, ClassUID: 3002, AssetID: e.AssetID, Username: e.Username, PartitionKey: e.AssetID.String()}
		if err := rows.Scan(&candidate.ID, &candidate.Timestamp, &candidate.Source, &candidate.Raw); err != nil {
			rows.Close()
			return 0, err
		}
		candidates = append(candidates, candidate)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	created := 0
	for _, candidate := range candidates {
		result, err := tx.ExecContext(ctx, `INSERT INTO temporal_matches(rule_id,event_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, sigma.RuleBruteforceSuccess, candidate.ID)
		if err != nil {
			return 0, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		if n == 0 {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal(candidate.Raw, &raw); err != nil {
			return 0, err
		}
		sigma.WithActor(raw, candidate.Username)
		// 抑制也消费本次命中，避免后续无关失败把历史命中反复拿来申请告警。
		if p.Suppress.Suppressed(sigma.RuleBruteforceSuccess, candidate.AssetID, raw, candidate.Timestamp) {
			continue
		}
		command, err := cmdorigin.Of(ctx, tx, raw, candidate.AssetID, candidate.Timestamp)
		if err != nil {
			return 0, err
		}
		fresh, err := p.upsertAlert(ctx, tx, candidate, intel.Hit{RuleID: sigma.RuleBruteforceSuccess, Severity: 5}, origin{command: command})
		if err != nil {
			return 0, err
		}
		if fresh {
			created++
		}
	}
	return created, nil
}
