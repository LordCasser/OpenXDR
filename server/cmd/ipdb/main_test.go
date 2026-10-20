package main

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/ipdb"
)

// 当月没发布退回上月；两份都校验过才替换，坏文件不落盘
func TestUpdate(t *testing.T) {
	fixtures := map[string]string{"asn": ipdb.ASNFile, "country": ipdb.CountryFile}
	broken := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := filepath.Base(r.URL.Path)
		if !strings.HasSuffix(name, "-2026-09.mmdb.gz") {
			http.NotFound(w, r)
			return
		}
		kind := strings.TrimSuffix(strings.TrimPrefix(name, "dbip-"), "-lite-2026-09.mmdb.gz")
		b, err := os.ReadFile(filepath.Join("..", "..", "internal", "ipdb", "testdata", fixtures[kind]))
		if err != nil {
			t.Error(err)
		}
		if broken && kind == "country" {
			b = []byte("<html>oops</html>")
		}
		zw := gzip.NewWriter(w)
		_, _ = zw.Write(b)
		_ = zw.Close()
	}))
	defer srv.Close()
	base = srv.URL
	dir := t.TempDir()
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

	if err := update(srv.Client(), dir, "", now); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		got, _ := os.ReadFile(filepath.Join(dir, f))
		want, _ := os.ReadFile(filepath.Join("..", "..", "internal", "ipdb", "testdata", f))
		if !bytes.Equal(got, want) {
			t.Fatalf("%s 内容不对", f)
		}
	}
	if err := update(srv.Client(), dir, "2026-08", now); err == nil {
		t.Fatal("指定的月份下不到应报错")
	}
	broken = true
	if err := update(srv.Client(), dir, "2026-09", now); err == nil {
		t.Fatal("校验不过应报错")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "NOTICE")); !strings.Contains(string(b), "2026-09") || !strings.Contains(string(b), "Creative Commons Attribution 4.0") {
		t.Fatalf("应写上许可与署名: %s", b)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 3 {
		t.Fatalf("失败后不该留临时文件: %v", entries)
	}
}
