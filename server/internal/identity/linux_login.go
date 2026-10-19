package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/google/uuid"
)

type LinuxLogin struct {
	Name    string
	Success bool
}

// LinuxLoginFromRaw 不把当前 passwd 或日志自报 UID 当作历史登录身份。
func LinuxLoginFromRaw(source, os string, class int, raw json.RawMessage) (*LinuxLogin, error) {
	if source != "agent" || os != "linux" || class != 3002 {
		return nil, nil
	}
	invalid := errors.New("Linux 登录观察字段无效")
	if len(raw) > 1024*1024 || !utf8.Valid(raw) {
		return nil, invalid
	}
	var event struct {
		EventID  json.RawMessage `json:"event_id"`
		LogName  json.RawMessage `json:"log_name"`
		Activity int             `json:"activity_id"`
		Status   int             `json:"status_id"`
		User     struct {
			Name string `json:"name"`
		} `json:"user"`
		Service struct {
			Name string `json:"name"`
		} `json:"service"`
	}
	if json.Unmarshal(raw, &event) != nil {
		return nil, invalid
	}
	if event.Activity != 1 || len(event.EventID) != 0 || len(event.LogName) != 0 {
		return nil, nil
	}
	if event.Status != 1 && event.Status != 2 || event.User.Name == "" || !localAccountText(event.User.Name, 256) || !localAccountText(event.Service.Name, 512) {
		return nil, invalid
	}
	return &LinuxLogin{Name: event.User.Name, Success: event.Status == 1}, nil
}

// ObserveLinuxLogin 仅记用户名观察，不生成账号键、SID 或会话 ID。
func ObserveLinuxLogin(ctx context.Context, tx *sql.Tx, eventID uuid.UUID) error {
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
	if os.String != "linux" {
		return nil
	}
	login, parseErr := LinuxLoginFromRaw(source, os.String, class, raw)
	if parseErr == nil && login == nil {
		return nil
	}
	state := "invalid"
	var name, success, groupValue any
	if parseErr == nil {
		state = "missing_uid"
		name = login.Name
		success = login.Success
	}
	if group.Valid {
		groupValue = group.UUID
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO identity_observations(event_id,asset_id,group_id,account_name,success,state)
 VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(event_id) DO NOTHING`, eventID, asset.UUID, groupValue, name, success, state)
	return err
}
