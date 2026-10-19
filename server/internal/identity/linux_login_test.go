package identity

import "testing"

func TestLinuxLoginDoesNotInventIdentity(t *testing.T) {
	for _, status := range []string{"1", "2"} {
		raw := []byte(`{"activity_id":1,"status_id":` + status + `,"user":{"name":"root","uid":"0"},"session":{"uid":"fake"},"service":{"name":"sshd"}}`)
		got, err := LinuxLoginFromRaw("agent", "linux", 3002, raw)
		if err != nil || got == nil || got.Name != "root" || got.Success != (status == "1") {
			t.Fatalf("%+v %v", got, err)
		}
	}
	for _, raw := range []string{`{}`, `{"activity_id":2}`} {
		got, err := LinuxLoginFromRaw("agent", "linux", 3002, []byte(raw))
		if err != nil || got != nil {
			t.Fatal("不支持的事件产生登录")
		}
	}
	for _, raw := range []string{`invalid`, `{"activity_id":1,"status_id":3,"user":{"name":"a"}}`, `{"activity_id":1,"status_id":1,"user":{"name":""}}`, `{"activity_id":1,"status_id":1,"user":{"name":"a\n"}}`} {
		got, err := LinuxLoginFromRaw("agent", "linux", 3002, []byte(raw))
		if err == nil || got != nil {
			t.Fatal("坏字段被接受")
		}
	}
	got, err := LinuxLoginFromRaw("agent", "windows", 3002, []byte("bad"))
	if err != nil || got != nil {
		t.Fatal("跨系统解析")
	}
}
