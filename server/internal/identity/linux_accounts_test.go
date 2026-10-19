package identity

import (
	"encoding/json"
	"strings"
	"testing"
)

func localRaw(state, items string) json.RawMessage {
	suffix := ""
	if items != "" {
		suffix = `,"items":` + items
	}
	return json.RawMessage(`{"activity_id":2,"device":{"local_accounts":{"version":1,"source":"etc-passwd","state":"` + state + `"` + suffix + `}}}`)
}

func TestLinuxAccountsStates(t *testing.T) {
	for _, tc := range []struct {
		state, items string
		count        int
	}{
		{"observed", "[]", 0}, {"unavailable", "", 0},
		{"observed", `[{"name":"root","uid":0,"gid":0,"shell":"/bin/sh"},{"name":"alias","uid":0,"gid":1,"shell":""}]`, 2},
	} {
		got, err := LinuxAccountsFromRaw("agent", "linux", 5001, localRaw(tc.state, tc.items))
		if err != nil || got == nil || got.State != tc.state || len(got.Items) != tc.count {
			t.Fatalf("%+v %v", got, err)
		}
		if (got.Items == nil) != (tc.state == "unavailable") {
			t.Fatal("清单状态混淆")
		}
	}
	for _, raw := range []json.RawMessage{json.RawMessage(`{"activity_id":2,"device":{}}`), json.RawMessage(`{"activity_id":1}`)} {
		got, err := LinuxAccountsFromRaw("agent", "linux", 5001, raw)
		if err != nil || got != nil {
			t.Fatal("无清单产生观察")
		}
	}
	for _, tc := range []struct {
		source, os string
		class      int
	}{{"sensor", "linux", 5001}, {"agent", "windows", 5001}, {"agent", "linux", 3002}} {
		got, err := LinuxAccountsFromRaw(tc.source, tc.os, tc.class, []byte(`invalid`))
		if err != nil || got != nil {
			t.Fatal("错误来源进入解析")
		}
	}
}

func TestLinuxAccountsRejectsPartial(t *testing.T) {
	row := `{"name":"u","uid":1,"gid":1,"shell":""}`
	bad := []json.RawMessage{localRaw("observed", ""), localRaw("observed", "null"), localRaw("unavailable", "[]"), localRaw("bad", "[]"), localRaw("observed", "["+row+","+row+"]"), localRaw("observed", "["+strings.Repeat(row+",", 512)+row+"]")}
	for _, items := range []string{`[{}]`, `[{"name":"u","gid":1,"shell":""}]`, `[{"name":"u","uid":-1,"gid":1,"shell":""}]`, `[{"name":"u","uid":4294967296,"gid":1,"shell":""}]`, `[{"name":"u\n","uid":1,"gid":1,"shell":""}]`, `[{"name":"u","uid":null,"gid":1,"shell":""}]`} {
		bad = append(bad, localRaw("observed", items))
	}
	bad = append(bad, []byte(strings.Repeat(" ", 1024*1024+1)), []byte{0xff})
	for _, raw := range bad {
		got, err := LinuxAccountsFromRaw("agent", "linux", 5001, raw)
		if err == nil || got != nil {
			t.Fatalf("坏清单未整体拒绝: %v", err)
		}
	}
}
