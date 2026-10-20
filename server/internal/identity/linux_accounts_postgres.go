package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

func ensureLocalAccountsSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS identity_local_snapshots (
 event_id uuid PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
 asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
 group_id uuid, state text NOT NULL CHECK(state IN ('observed','unavailable','invalid')),
 source text NOT NULL CHECK(source='etc-passwd'));
 CREATE INDEX IF NOT EXISTS identity_local_snapshots_asset ON identity_local_snapshots(asset_id,group_id);
 CREATE TABLE IF NOT EXISTS identity_local_accounts (
 event_id uuid NOT NULL REFERENCES identity_local_snapshots(event_id) ON DELETE CASCADE,
 name text NOT NULL, uid bigint NOT NULL CHECK(uid BETWEEN 0 AND 4294967295),
 gid bigint NOT NULL CHECK(gid BETWEEN 0 AND 4294967295), shell text NOT NULL,
 PRIMARY KEY(event_id,name));`)
	return err
}

// ObserveLinuxAccounts 保存逐事件快照，迟到清单不覆盖新观察，缺失账号不推断删除。
// 事件和归组均取自数据库；组表示接收时归属，不推断离线采集时的归属。
func ObserveLinuxAccounts(ctx context.Context, tx *sql.Tx, eventID uuid.UUID) error {
	var source string
	var class int
	var raw json.RawMessage
	var asset uuid.NullUUID
	var ts time.Time
	if err := tx.QueryRowContext(ctx, `SELECT source,class_uid,raw,asset_id,ts FROM events WHERE id=$1`, eventID).Scan(&source, &class, &raw, &asset, &ts); err != nil {
		return err
	}
	if source != "agent" || class != 5001 || !asset.Valid {
		return nil
	}
	var os sql.NullString
	var group uuid.NullUUID
	if err := tx.QueryRowContext(ctx, `SELECT os,group_id FROM assets WHERE id=$1 FOR SHARE`, asset.UUID).Scan(&os, &group); err != nil {
		return err
	}
	if os.String != "linux" {
		return nil
	}
	snapshot, parseErr := LinuxAccountsFromRaw(source, os.String, class, raw)
	if parseErr == nil && snapshot == nil {
		return nil
	}
	state := "invalid"
	if parseErr == nil {
		state = snapshot.State
	}
	var groupValue any
	if group.Valid {
		groupValue = group.UUID
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO identity_local_snapshots(event_id,asset_id,group_id,state,source,ts)
 VALUES($1,$2,$3,$4,'etc-passwd',$5) ON CONFLICT(event_id) DO NOTHING`, eventID, asset.UUID, groupValue, state, ts)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil || inserted == 0 || state != "observed" {
		return err
	}
	for _, account := range snapshot.Items {
		if _, err := tx.ExecContext(ctx, `INSERT INTO identity_local_accounts(event_id,name,uid,gid,shell) VALUES($1,$2,$3,$4,$5)`, eventID, account.Name, int64(account.UID), int64(account.GID), account.Shell); err != nil {
			return err
		}
	}
	return nil
}
