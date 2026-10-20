package automation

import (
	"testing"

	"openxdr/server/internal/sigma"
)

const fp = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"

func TestSession(t *testing.T) {
	raw := map[string]any{"login_session": map[string]any{
		"uid": "12", "user": "root", "src_ip": "10.1.1.35", "key_fp": fp, "auth_method": "publickey",
	}}
	l, ok := Session(raw)
	if !ok || l.User != "root" || l.SrcIP != "10.1.1.35" || l.KeyFP != fp || l.Method != "publickey" {
		t.Fatalf("解析错误: %+v %v", l, ok)
	}
	if _, ok := Session(map[string]any{}); ok {
		t.Fatal("没有登录归属不应认出")
	}
	if _, ok := Session(map[string]any{"login_session": "x"}); ok {
		t.Fatal("类型不对不应认出")
	}
	if _, ok := Session(map[string]any{"login_session": map[string]any{"user": "root"}}); ok {
		t.Fatal("只有用户名不够认")
	}
}

func TestWatch(t *testing.T) {
	rules := []*sigma.Rule{
		{ID: "recon", Tactics: []string{"discovery"}, Techniques: []string{"T1082"}},
		{ID: "revshell", Severity: 5, Tactics: []string{"execution", "command-and-control"}, Techniques: []string{"T1059.004"}},
		{ID: "dump", Tactics: []string{"credential-access"}, Techniques: []string{"T1003.008"}},
		{ID: "logclear", Tactics: []string{"defense-evasion"}, Techniques: []string{"T1070.002"}},
		{ID: "auditoff", Tactics: []string{"defense-evasion"}, Techniques: []string{"T1562.012"}},
		{ID: "wipe", Tactics: []string{"impact"}},
		{ID: "lookalike", Techniques: []string{"T10700"}},
	}
	cases := map[string]bool{
		"recon": false, "revshell": false, "lookalike": false,
		"dump": true, "logclear": true, "auditoff": true, "wipe": true,
		"intel:ip:1.2.3.4": true,
		"不在命中列表里":          true,
	}
	for id, want := range cases {
		if got := Watch(id, rules); got != want {
			t.Errorf("%s: Watch=%v，期望 %v", id, got, want)
		}
	}
}

func TestNormalize(t *testing.T) {
	ok := []struct {
		in   Criteria
		cidr string
	}{
		{Criteria{KeyFingerprint: fp}, ""},
		{Criteria{KeyFingerprint: " " + fp + " ", SourceCIDR: "10.1.1.35", LoginUser: "root"}, "10.1.1.35/32"},
		{Criteria{SourceCIDR: "10.1.1.77/24"}, "10.1.1.0/24"},
		{Criteria{SourceCIDR: "::ffff:10.1.1.35"}, "10.1.1.35/32"},
		{Criteria{SourceCIDR: "fd00::1/64"}, "fd00::/64"},
		{Criteria{KeyFingerprint: fp, SourceCIDR: "10.0.0.0/8"}, "10.0.0.0/8"},
	}
	for _, c := range ok {
		got, err := c.in.Normalize()
		if err != nil {
			t.Fatalf("%+v: %v", c.in, err)
		}
		if got.SourceCIDR != c.cidr || (c.in.KeyFingerprint != "" && got.KeyFingerprint != fp) {
			t.Fatalf("%+v 规范化成 %+v", c.in, got)
		}
	}
	bad := []Criteria{
		{},
		{LoginUser: "root"},
		{KeyFingerprint: "SHA256:short"},
		{KeyFingerprint: "MD5:aa:bb"},
		{SourceCIDR: "not-an-ip"},
		{SourceCIDR: "10.0.0.0/8"},
		{SourceCIDR: "0.0.0.0/0"},
		{SourceCIDR: "fd00::/48"},
		{KeyFingerprint: fp, LoginUser: "a b"},
	}
	for _, c := range bad {
		if _, err := c.Normalize(); err == nil {
			t.Fatalf("%+v 应被拒绝", c)
		}
	}
}
