// Package identity 从实际身份遥测提取可追溯标识，不按显示名猜测账号等价关系。
package identity

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"openxdr/server/internal/identity/sid"
)

type WindowsLogin struct {
	SID     string
	Name    string
	Domain  string
	LogonID string
	Success bool
}

// WindowsLoginFromRaw 只接受已归一化的 Agent Security 4624/4625 登录事件。
// source/OS/class 应来自可信接入信封，不从 raw 中采信资产或组。
func WindowsLoginFromRaw(source, os string, class int, raw json.RawMessage) (*WindowsLogin, error) {
	if source != "agent" || os != "windows" || class != 3002 {
		return nil, nil
	}
	var event struct {
		EventID  int    `json:"event_id"`
		LogName  string `json:"log_name"`
		Activity int    `json:"activity_id"`
		Status   int    `json:"status_id"`
		User     struct {
			UID    string `json:"uid"`
			Name   string `json:"name"`
			Domain string `json:"domain"`
		} `json:"user"`
		Session struct {
			UID string `json:"uid"`
		} `json:"session"`
	}
	if err := json.Unmarshal(raw, &event); err != nil {
		return nil, err
	}
	if event.LogName != "Security" || (event.EventID != 4624 && event.EventID != 4625) {
		return nil, nil
	}
	expected := 1
	if event.EventID == 4625 {
		expected = 2
	}
	if event.Activity != 1 || event.Status != expected {
		return nil, fmt.Errorf("Windows 登录事件类型与结果冲突")
	}
	login := &WindowsLogin{Name: event.User.Name, Domain: event.User.Domain, Success: expected == 1}
	if event.User.UID != "" && event.User.UID != "-" && event.User.UID != "S-1-0-0" {
		sid, err := canonicalSID(event.User.UID)
		if err != nil {
			return nil, err
		}
		login.SID = sid
	}
	if login.Success && event.Session.UID != "" {
		value, ok := strings.CutPrefix(event.Session.UID, "0x")
		if !ok {
			return nil, fmt.Errorf("目标 Logon ID 格式无效")
		}
		n, err := strconv.ParseUint(value, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("目标 Logon ID 格式无效")
		}
		if n != 0 {
			login.LogonID = fmt.Sprintf("0x%x", n)
		}
	}
	return login, nil
}

// AccountKey 暂按组和设备限定 SID；目录权威来源验证前不跨主机合并本地/域账户。
// Logon ID 不参与账号身份，也不单独构造跨重启会话身份。
func (l WindowsLogin) AccountKey(group, asset uuid.UUID) (string, bool) {
	if group == uuid.Nil || asset == uuid.Nil || l.SID == "" {
		return "", false
	}
	sid, err := canonicalSID(l.SID)
	if err != nil || sid == "" {
		return "", false
	}
	return "windows-sid:" + group.String() + ":" + asset.String() + ":" + sid, true
}

func canonicalSID(value string) (string, error) { return sid.Canonical(value) }
