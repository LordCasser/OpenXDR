package identity

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/google/uuid"
	"openxdr/server/internal/identity/directory"
)

func EnsureSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS identity_observations (
 event_id uuid PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
 asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
 group_id uuid, account_key text, account_sid text, account_name text, account_domain text,
 logon_id text, success boolean, state text NOT NULL, detail text NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS identity_observations_account ON identity_observations(group_id,account_key);
CREATE INDEX IF NOT EXISTS identity_observations_asset ON identity_observations(asset_id);`)
	if err != nil {
		return err
	}
	if err := ensureLocalAccountsSchema(ctx, db); err != nil {
		return err
	}
	return directory.EnsureSchema(ctx, db)
}

// ObserveWindows 在事件首次插入的事务内记录来源观察；解析不支持的来源不造关系，
// 坏字段记 invalid 并保留原始事件，不让身份增强失败吞掉检测证据。
func ObserveWindows(ctx context.Context, tx *sql.Tx, eventID uuid.UUID) error {
	var source string
	var class int
	var raw json.RawMessage
	var asset uuid.NullUUID
	if err := tx.QueryRowContext(ctx, `SELECT source,class_uid,raw,asset_id FROM events WHERE id=$1`, eventID).Scan(&source, &class, &raw, &asset); err != nil {
		return err
	}
	if source != "agent" || class != 3002 || !asset.Valid {
		return nil
	}
	var os sql.NullString
	var group uuid.NullUUID
	if err := tx.QueryRowContext(ctx, `SELECT os,group_id FROM assets WHERE id=$1 FOR SHARE`, asset.UUID).Scan(&os, &group); err != nil {
		return err
	}
	if os.String != "windows" {
		return nil
	}
	login, parseErr := WindowsLoginFromRaw(source, os.String, class, raw)
	if parseErr == nil && login == nil {
		return nil
	}
	state, detail := "observed", ""
	var key, sid, name, domain, session any
	var success any
	if parseErr != nil {
		state, detail = "invalid", parseErr.Error()
	} else {
		sid, name, domain, success = nullable(login.SID), nullable(login.Name), nullable(login.Domain), login.Success
		session = nullable(login.LogonID)
		if value, ok := login.AccountKey(group.UUID, asset.UUID); ok {
			key = value
		} else if !group.Valid || group.UUID == uuid.Nil {
			state = "unscoped"
		} else {
			state = "missing_sid"
		}
	}
	var groupValue any
	if group.Valid {
		groupValue = group.UUID
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO identity_observations
(event_id,asset_id,group_id,account_key,account_sid,account_name,account_domain,logon_id,success,state,detail)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(event_id) DO NOTHING`, eventID, asset.UUID, groupValue, key, sid, name, domain, session, success, state, detail)
	return err
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}
