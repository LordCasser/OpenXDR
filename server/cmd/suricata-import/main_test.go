package main

import (
	"cmp"
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

const testAlert = `{"timestamp":"2026-10-21T10:20:30+0800","event_type":"alert","flow_id":42,"src_ip":"198.51.100.2","src_port":12345,"dest_ip":"10.0.0.2","dest_port":80,"proto":"TCP","alert":{"gid":1,"signature_id":100001,"rev":2,"signature":"受控测试","severity":1}}`

func TestImportStopsAndCanReplay(t *testing.T) {
	token := strings.Repeat("a", 32)
	calls := 0
	status := map[int]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("Content-Type") != "application/json" {
			t.Error("鉴权或内容类型丢失")
		}
		w.WriteHeader(cmp.Or(status[calls], 202))
	}))
	defer server.Close()
	input := `{"event_type":"flow"}` + "\n" + testAlert + "\n" + testAlert + "\n" + testAlert + "\n"
	status = map[int]int{2: 503}
	n, _, err := run(context.Background(), strings.NewReader(input), server.Client(), server.URL, token)
	if n != 1 || err == nil || calls != 2 {
		t.Fatalf("暂时故障应停止: count=%d calls=%d err=%v", n, calls, err)
	}
	status, calls = nil, 0
	n, skipped, err := run(context.Background(), strings.NewReader(input), server.Client(), server.URL, token)
	if n != 3 || err != nil || calls != 3 || len(skipped) != 0 {
		t.Fatalf("重跑失败: %d %d %v", n, calls, err)
	}
	// 无效行和服务端 400 跳过并记行号，后面的告警照常导入
	bad := strings.Replace(testAlert, `"gid":1`, `"gid":0`, 1)
	status, calls = map[int]int{2: 400}, 0
	n, skipped, err = run(context.Background(), strings.NewReader("bad\n"+bad+"\n"+testAlert+"\n"+testAlert+"\n"+testAlert+"\n"), server.Client(), server.URL, token)
	if n != 2 || err != nil || calls != 3 || !slices.Equal(skipped, []int{1, 2, 4}) {
		t.Fatalf("跳过无效行: count=%d calls=%d skipped=%v err=%v", n, calls, skipped, err)
	}
	if _, _, err := run(context.Background(), strings.NewReader(strings.Repeat("x", 256<<10+2)), server.Client(), server.URL, token); err == nil {
		t.Fatal("过大行必须报错")
	}
	if _, _, err := run(context.Background(), strings.NewReader(testAlert), server.Client(), "http://remote.example/api", token); err == nil {
		t.Fatal("不能明文发送远程密钥")
	}
}
