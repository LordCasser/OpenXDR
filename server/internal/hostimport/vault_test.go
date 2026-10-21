package hostimport

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	master := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	a, err := DeriveKey(master, "openxdr/integration-cursor/v1")
	if err != nil || len(a) != 32 {
		t.Fatal(err)
	}
	again, _ := DeriveKey(master, "openxdr/integration-cursor/v1")
	other, _ := DeriveKey(master, "openxdr/other/v1")
	if !bytes.Equal(a, again) || bytes.Equal(a, other) || bytes.Equal(a, []byte(strings.Repeat("k", 32))) {
		t.Fatal("派生须确定、按用途隔离且不等于主密钥")
	}
	if _, err := DeriveKey("short", "x"); err == nil {
		t.Fatal("无效主密钥应拒绝")
	}
}
