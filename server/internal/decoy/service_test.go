package decoy

import (
	"strings"
	"testing"
)

func TestServiceUnit(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	for _, kind := range []string{"ssh", "http", "file"} {
		unit, err := ServiceUnit("https://aidr.internal:8443", id, kind, "127.0.0.1", "/srv/share")
		if err != nil {
			t.Fatal(err)
		}
		// 文件载体不用动态用户：私有状态目录对业务用户不可见。
		if strings.Contains(unit, "DynamicUser=yes") == (kind == "file") || strings.Contains(unit, "ReadWritePaths=/srv/share") != (kind == "file") {
			t.Fatal("file sandbox mismatch", kind)
		}
		for _, want := range []string{"Restart=no", "-token-file %d/token", "CapabilityBoundingSet=", "LoadCredential=token:/etc/aidr-decoy/" + id + "/token"} {
			if !strings.Contains(unit, want) {
				t.Fatalf("missing %s", want)
			}
		}
		if strings.Contains(unit, "DECOY_RUNTIME_TOKEN") {
			t.Fatal("secret environment in unit")
		}
		if strings.Contains(unit, "LoadCredential=host-key:") != (kind == "ssh") {
			t.Fatal("host key carrier mismatch")
		}
	}
	for _, origin := range []string{"http://aidr.internal", "https://user:pass@aidr.internal", "https://aidr.internal/a", "https://aidr.internal?x=1", "https://aidr.internal#x", "https://aidr.internal\nExecStart=/bin/sh", "https://aidr.internal/%n", "https://${HOST}", "https://aidr.internal:bad"} {
		if _, err := ServiceUnit(origin, id, "http", "127.0.0.1", ""); err == nil {
			t.Fatalf("accepted origin %q", origin)
		}
	}
	for _, bad := range []string{"../test", "%i", "11111111111141118111111111111111", "00000000-0000-0000-0000-000000000000"} {
		if _, err := ServiceUnit("https://aidr.internal", bad, "http", "127.0.0.1", ""); err == nil {
			t.Fatal("accepted invalid ID")
		}
	}
	if _, err := ServiceUnit("https://aidr.internal", id, "shell", "127.0.0.1", ""); err == nil {
		t.Fatal("accepted shell daemon")
	}
	if _, err := ServiceUnit("https://aidr.internal", id, "http", "localhost\nRestart=always", ""); err == nil {
		t.Fatal("accepted listen injection")
	}
	for _, root := range []string{"", "/", "relative", "/srv/../etc", "/srv/a b", "/srv/%n", "/etc/x", "/opt/aidr-decoy/x", "/proc", "/srv/share/"} {
		if _, err := ServiceUnit("https://aidr.internal", id, "file", "127.0.0.1", root); err == nil {
			t.Fatalf("accepted file root %q", root)
		}
	}
}
