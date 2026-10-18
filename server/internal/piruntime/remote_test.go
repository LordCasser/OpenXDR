package piruntime

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testKey = "0123456789abcdef0123456789abcdef"

// 模拟 sandboxd：同一条流上先读请求、发工具请求、读工具结果，再给最终结果——必须真正全双工才能走完
func fakeSandbox(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 与 sandboxd 一致：先开全双工再判密钥，拒绝时才不会卡在读请求体上
		rc := http.NewResponseController(w)
		_ = rc.EnableFullDuplex()
		if r.Header.Get("Authorization") != "Bearer "+testKey {
			http.Error(w, "密钥无效", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = rc.Flush()
		in := bufio.NewScanner(r.Body)
		send := func(v any) {
			b, _ := json.Marshal(v)
			_, _ = w.Write(append(b, '\n'))
			_ = rc.Flush()
		}
		in.Scan()
		var req Request
		_ = json.Unmarshal(in.Bytes(), &req)
		send(map[string]any{"type": "tool_request", "call_id": "1", "name": "exec", "args": map[string]string{"host": "h"}})
		in.Scan()
		var reply struct {
			Output string `json:"output"`
		}
		_ = json.Unmarshal(in.Bytes(), &reply)
		send(map[string]any{"type": "result", "response": req.Prompt + ":" + reply.Output + ":" + string(req.Context), "stop_reason": "stop", "turns": 1})
	}))
}

func TestRemoteRoundTrip(t *testing.T) {
	srv := fakeSandbox(t)
	defer srv.Close()
	remote, err := NewRemote(srv.URL, testKey, "")
	if err != nil {
		t.Fatal(err)
	}
	rt := Runtime{Remote: remote, Timeout: 10 * time.Second}
	handle := func(_ context.Context, name string, _ json.RawMessage) (string, error) { return "ran-" + name, nil }
	res, err := rt.Run(context.Background(), Request{Prompt: "hi", Context: json.RawMessage(`{"a":1}`), Tools: []Tool{{Name: "exec"}}}, handle,
		func(context.Context, Event) error { return nil })
	if err != nil || res.Response != `hi:ran-exec:{"a":1}` {
		t.Fatalf("全双工往返: %+v %v", res, err)
	}
}

func TestRemoteRejectsBadKey(t *testing.T) {
	srv := fakeSandbox(t)
	defer srv.Close()
	remote, _ := NewRemote(srv.URL, strings.Repeat("x", 32), "")
	_, err := Runtime{Remote: remote}.Run(context.Background(), Request{Prompt: "hi"}, nil, func(context.Context, Event) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("错误密钥应被拒: %v", err)
	}
	if _, err := NewRemote(srv.URL, "short", ""); err == nil {
		t.Fatal("过短密钥应拒绝")
	}
}
