package agentchat

import (
	"strings"
	"testing"
)

// 每个对象都要单独列出来，个数写明：模型靠这份清单判断还剩几个没做
func TestRoster(t *testing.T) {
	title := "反弹 shell"
	got := roster([]map[string]any{
		{"kind": "finding", "hostname": "pve2", "key": "rsync-daemon", "title": "rsync 空守护进程"},
		{"kind": "incident", "id": "01a1", "title": &title},
		{"kind": "incident", "id": "01a2", "title": (*string)(nil)},
	})
	for _, want := range []string{"交给你 3 个对象", "1. 待办 pve2 / rsync-daemon：rsync 空守护进程", "2. 事件 01a1：反弹 shell", "3. 事件 01a2：（无标题）"} {
		if !strings.Contains(got, want) {
			t.Fatalf("清单缺少 %q：%s", want, got)
		}
	}
}
