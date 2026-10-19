package ingest

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/google/uuid"
	"openxdr/server/internal/cmdorigin"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/temporal"
)

func (p *Processor) temporalAlert(ctx context.Context, tx *sql.Tx, match temporal.Match) (bool, error) {
	asset, err := uuid.Parse(match.Scope.Entity)
	if err != nil {
		return false, err
	}
	e := Envelope{ID: match.Anchor, AssetID: &asset, PartitionKey: match.Scope.Entity,
		FingerprintSuffix: "|temporal:" + match.Revision + "|group:" + match.Scope.Group.String()}
	var username sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT ts,class_uid,source,username,raw FROM events WHERE id=$1 AND asset_id=$2`, match.Anchor, asset).
		Scan(&e.Timestamp, &e.ClassUID, &e.Source, &username, &e.Raw); err != nil {
		return false, err
	}
	e.Username = username.String
	var raw map[string]any
	if err := json.Unmarshal(e.Raw, &raw); err != nil {
		return false, err
	}
	sigma.WithActor(raw, e.Username)
	if p.Suppress.Suppressed(match.RuleID, e.AssetID, raw, e.Timestamp) {
		return false, nil
	}
	command, err := cmdorigin.Of(ctx, tx, raw, e.AssetID, e.Timestamp)
	if err != nil {
		return false, err
	}
	hit := intel.Hit{RuleID: match.RuleID, Severity: match.Severity}
	created, err := p.upsertAlert(ctx, tx, e, hit, command)
	if err != nil {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE temporal_detections SET alert_id=(SELECT alert_id FROM alert_dedup_state WHERE fingerprint=$1)
WHERE revision=$2 AND rule_id=$3 AND anchor_id=$4`, alertFingerprint(e, hit, command), match.Revision, match.RuleID, match.Anchor)
	return created, err
}
