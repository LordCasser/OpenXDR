package identity

import (
	"bytes"
	"encoding/json"
	"errors"
	"unicode"
	"unicode/utf8"
)

// LinuxAccount 是一次 passwd 观察，不代表跨时间稳定的主体或启用状态。
type LinuxAccount struct {
	Name  string `json:"name"`
	UID   uint32 `json:"uid"`
	GID   uint32 `json:"gid"`
	Shell string `json:"shell"`
}

type LinuxAccounts struct {
	State string
	Items []LinuxAccount
}

// LinuxAccountsFromRaw 的来源、系统与类型必须来自可信接入信封。
// nil 表示没有支持的清单；unavailable 与 observed 空数组分别保留。
func LinuxAccountsFromRaw(source, os string, class int, raw json.RawMessage) (*LinuxAccounts, error) {
	if source != "agent" || os != "linux" || class != 5001 {
		return nil, nil
	}
	invalid := errors.New("本地账号清单格式无效或超过上限")
	if len(raw) > 1024*1024 || !utf8.Valid(raw) {
		return nil, invalid
	}
	var event struct {
		Activity int `json:"activity_id"`
		Device   struct {
			Accounts json.RawMessage `json:"local_accounts"`
		} `json:"device"`
	}
	if json.Unmarshal(raw, &event) != nil {
		return nil, invalid
	}
	if event.Activity != 2 || len(event.Device.Accounts) == 0 {
		return nil, nil
	}
	var snapshot struct {
		Version int             `json:"version"`
		Source  string          `json:"source"`
		State   string          `json:"state"`
		Items   json.RawMessage `json:"items"`
	}
	if json.Unmarshal(event.Device.Accounts, &snapshot) != nil || snapshot.Version != 1 || snapshot.Source != "etc-passwd" {
		return nil, invalid
	}
	result := &LinuxAccounts{State: snapshot.State}
	if snapshot.State == "unavailable" {
		if len(snapshot.Items) != 0 {
			return nil, invalid
		}
		return result, nil
	}
	if snapshot.State != "observed" || len(snapshot.Items) == 0 || bytes.Equal(bytes.TrimSpace(snapshot.Items), []byte("null")) {
		return nil, invalid
	}
	var rows []struct {
		Name  *string `json:"name"`
		UID   *uint32 `json:"uid"`
		GID   *uint32 `json:"gid"`
		Shell *string `json:"shell"`
	}
	if json.Unmarshal(snapshot.Items, &rows) != nil || len(rows) > 512 {
		return nil, invalid
	}
	result.Items = make([]LinuxAccount, 0, len(rows))
	names := make(map[string]bool, len(rows))
	for _, row := range rows {
		if row.Name == nil || row.UID == nil || row.GID == nil || row.Shell == nil {
			return nil, invalid
		}
		if !localAccountText(*row.Name, 256) || *row.Name == "" || !localAccountText(*row.Shell, 512) || names[*row.Name] {
			return nil, invalid
		}
		names[*row.Name] = true
		result.Items = append(result.Items, LinuxAccount{Name: *row.Name, UID: *row.UID, GID: *row.GID, Shell: *row.Shell})
	}
	return result, nil
}

func localAccountText(value string, limit int) bool {
	if len(value) > limit {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return false
		}
	}
	return true
}
