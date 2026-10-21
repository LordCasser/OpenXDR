package integration

import (
	"net/netip"
	"testing"
)

func TestOutboundPolicy(t *testing.T) {
	p, err := ParseOutboundPolicy("hooks.example.test,10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host, ip string
		want     bool
	}{
		{"hooks.example.test", "127.0.0.1", false}, {"hooks.example.test", "169.254.169.254", false},
		{"hooks.example.test", "100.100.100.200", false}, {"other.test", "10.1.1.1", true},
		{"other.test", "192.168.1.1", false}, {"hooks.example.test", "192.168.1.1", true},
		{"hooks.example.test", "::ffff:127.0.0.1", false}, {"public.test", "8.8.8.8", true},
	} {
		if got := p.permits(tc.host, netip.MustParseAddr(tc.ip)); got != tc.want {
			t.Errorf("%+v: %v", tc, got)
		}
	}
	for _, url := range []string{"http://example.test", "https://user:pass@example.test", "https://example.test/?secret=x", "https://example.test/#x", "https://example.test:99999"} {
		if _, err = ValidateTarget(url); err == nil {
			t.Errorf("接受无效目标 %s", url)
		}
	}
}
func TestWebhookSignature(t *testing.T) {
	key := []byte("key")
	first := SignEvent(key, "123", "event", []byte(`{"status":"open"}`))
	for _, got := range []string{SignEvent(key, "124", "event", []byte(`{"status":"open"}`)), SignEvent(key, "123", "other", []byte(`{"status":"open"}`)), SignEvent(key, "123", "event", []byte(`{"status":"closed"}`))} {
		if got == first {
			t.Fatal("签名没有绑定完整消息")
		}
	}
}
