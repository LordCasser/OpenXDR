package identity

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func loginRaw(id, status int, sid, domain, session string) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{"event_id": id, "log_name": "Security", "activity_id": 1, "status_id": status,
		"user": map[string]string{"uid": sid, "name": "alice", "domain": domain}, "session": map[string]string{"uid": session}})
	return raw
}
func TestWindowsTargetIdentityAndBoundaries(t *testing.T) {
	login, err := WindowsLoginFromRaw("agent", "windows", 3002, loginRaw(4624, 1, "S-1-5-21-1-2-3-1001", "CONTOSO", "0x00ABC"))
	if err != nil || login == nil || login.SID != "S-1-5-21-1-2-3-1001" || login.Domain != "CONTOSO" || login.LogonID != "0xabc" || !login.Success {
		t.Fatalf("%+v %v", login, err)
	}
	group, asset := uuid.New(), uuid.New()
	key, ok := login.AccountKey(group, asset)
	if !ok {
		t.Fatal("有效 SID 应有受限账号键")
	}
	other, _ := login.AccountKey(group, uuid.New())
	if key == other {
		t.Fatal("不能跨设备合并")
	}
	other, _ = login.AccountKey(uuid.New(), asset)
	if key == other {
		t.Fatal("不能跨组合并")
	}
	if _, ok := login.AccountKey(uuid.Nil, asset); ok {
		t.Fatal("缺少组不能产生身份绑定")
	}
	for _, sid := range []string{"", "-", "S-1-0-0"} {
		failed, err := WindowsLoginFromRaw("agent", "windows", 3002, loginRaw(4625, 2, sid, "CONTOSO", "0x123"))
		if err != nil || failed == nil || failed.LogonID != "" || failed.Success {
			t.Fatalf("失败登录不能变成目标会话: %+v %v", failed, err)
		}
		if _, ok := failed.AccountKey(group, asset); ok {
			t.Fatal("不能用用户名替代缺失 SID")
		}
	}
}
func TestWindowsIdentityRejectsConflictsAndWrongSources(t *testing.T) {
	for _, raw := range []json.RawMessage{
		loginRaw(4624, 2, "S-1-5-21-1-2-3-1001", "DOMAIN", "0x1"),
		loginRaw(4624, 1, "alice", "DOMAIN", "0x1"),
		loginRaw(4624, 1, "S-1-5-4294967296", "DOMAIN", "0x1"),
		loginRaw(4624, 1, "S-1-5-21-1-2-3-1001", "DOMAIN", "invalid"),
	} {
		if _, err := WindowsLoginFromRaw("agent", "windows", 3002, raw); err == nil {
			t.Fatalf("无效输入未拒绝: %s", raw)
		}
	}
	raw := loginRaw(4624, 1, "S-1-5-21-1-2-3-1001", "DOMAIN", "0x1")
	for _, source := range []struct {
		source, os string
		class      int
	}{{"syslog", "windows", 3002}, {"agent", "linux", 3002}, {"agent", "windows", 1007}} {
		got, err := WindowsLoginFromRaw(source.source, source.os, source.class, raw)
		if err != nil || got != nil {
			t.Fatal("错误来源不能归一化为 Windows 登录")
		}
	}
}
