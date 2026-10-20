package vuln

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDownload(t *testing.T) {
	chunkSize, chunkTimeout = 1000, 200*time.Millisecond
	t.Cleanup(func() { chunkSize, chunkTimeout = 8<<20, 90*time.Second })
	data := make([]byte, 3500)
	rand.Read(data)
	var calls atomic.Int32
	mode := "range"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		switch {
		case mode == "flaky" && strings.HasPrefix(r.Header.Get("Range"), "bytes=1000-") && n == 2:
			http.Error(w, "boom", http.StatusBadGateway) // 第二段第一次失败
			return
		case mode == "stall" && strings.HasPrefix(r.Header.Get("Range"), "bytes=2000-") && n == 3:
			time.Sleep(time.Second) // 第三段第一次卡住，超过每段时限
		case mode == "norange":
			w.Write(data)
			return
		}
		http.ServeContent(w, r, "all.zip", time.Time{}, bytes.NewReader(data))
	}))
	t.Cleanup(srv.Close)
	s := &Syncer{}
	for _, m := range []string{"range", "flaky", "stall", "norange"} {
		mode = m
		calls.Store(0)
		var out bytes.Buffer
		if err := s.download(context.Background(), srv.URL, &out); err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		if !bytes.Equal(out.Bytes(), data) {
			t.Fatalf("%s: 内容不一致（%d / %d 字节）", m, out.Len(), len(data))
		}
	}
	// 大小恰好是分段整数倍：靠 416 收尾
	data = data[:3000]
	mode = "range"
	var out bytes.Buffer
	if err := s.download(context.Background(), srv.URL, &out); err != nil || !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("整数倍大小下载不对: %v %d", err, out.Len())
	}
}
