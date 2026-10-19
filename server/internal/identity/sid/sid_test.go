package sid

import (
	"encoding/hex"
	"testing"
)

func TestBinarySID(t *testing.T) {
	for _, test := range []struct{ raw, want string }{
		{"010500000000000515000000010000000200000003000000e9030000", "S-1-5-21-1-2-3-1001"},
		{"0101ffffffffffffffffffff", "S-1-281474976710655-4294967295"},
		{"010100000000000000000000", ""},
	} {
		raw, _ := hex.DecodeString(test.raw)
		got, err := FromBinary(raw)
		if err != nil || got != test.want {
			t.Fatalf("二进制 SID: %q %v", got, err)
		}
	}
	for _, value := range []string{"", "0100", "020100000000000501000000", "010200000000000501000000", "01010000000000050100000000", "0110000000000005"} {
		raw, _ := hex.DecodeString(value)
		if _, err := FromBinary(raw); err == nil {
			t.Fatalf("接受损坏 SID %s", value)
		}
	}
}

func TestTextSID(t *testing.T) {
	got, err := Canonical("S-1-005-021-0001")
	if err != nil || got != "S-1-5-21-1" {
		t.Fatal("文本未规范化")
	}
	for _, value := range []string{"S-2-5-21", "S-1-5-4294967296", "S-1-281474976710656-1", "S-1-5--1", "S-1-5-x"} {
		if _, err := Canonical(value); err == nil {
			t.Fatalf("接受无效 SID %s", value)
		}
	}
}
