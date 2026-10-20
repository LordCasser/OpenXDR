package liveness

import (
	"encoding/json"
	"testing"
)

// 活性检测的降级带原因：进通知文字，也进签名——同一能力从自报降级变成静默降级要重新通知
func TestHealthProblemsSilentReason(t *testing.T) {
	parse := func(raw string) healthSnapshot {
		t.Helper()
		var h healthSnapshot
		if err := json.Unmarshal([]byte(raw), &h); err != nil {
			t.Fatal(err)
		}
		return h
	}
	plain := healthProblems(parse(`{"capabilities":{"process":{"path":"etw","state":"degraded"}}}`), false, 0)
	silent := healthProblems(parse(`{"capabilities":{"process":{"path":"etw","state":"degraded","reason":"持续 5 分钟收不到进程事件，自检进程也没被看到"}}}`), false, 0)
	if len(plain) != 1 || len(silent) != 1 {
		t.Fatalf("应各有一项问题: %v %v", plain, silent)
	}
	if want := "进程采集降级（etw）：持续 5 分钟收不到进程事件，自检进程也没被看到"; silent[0].text != want {
		t.Fatalf("通知文字 = %q", silent[0].text)
	}
	if signature(plain) == signature(silent) {
		t.Fatal("静默降级与自报降级签名相同，不会重新通知")
	}
	// 自动重建的次数写进文字、不进签名：每重建一次都重新推送就刷屏了
	rebuilt := healthProblems(parse(`{"capabilities":{"process":{"path":"etw","state":"degraded","reason":"持续 5 分钟收不到进程事件，自检进程也没被看到","rebuilds":2}}}`), false, 0)
	if want := "进程采集降级（etw）：持续 5 分钟收不到进程事件，自检进程也没被看到（已自动重建 2 次仍未恢复）"; len(rebuilt) != 1 || rebuilt[0].text != want {
		t.Fatalf("通知文字 = %v", rebuilt)
	}
	if signature(rebuilt) != signature(silent) {
		t.Fatal("重建次数变了不应改签名")
	}
	if ps := healthProblems(parse(`{"capabilities":{"process":{"path":"etw","state":"active","recoveries":1}}}`), false, 0); len(ps) != 0 {
		t.Fatalf("自动恢复后不应有问题: %v", ps)
	}
	if ps := healthProblems(parse(`{"capabilities":{"process":{"path":"etw","state":"active"}}}`), false, 0); len(ps) != 0 {
		t.Fatalf("恢复后不应有问题: %v", ps)
	}
}
