package commandgate

import "testing"

func TestSearchIsUnanchored(t *testing.T) {
	for _, tc := range []struct {
		pattern, cmd string
		want         bool
	}{
		{`whoami`, `whoami`, true}, {`whoami`, `id; whoami`, true}, {`\brm\s+-rf`, `x && rm -rf /`, true},
		{`\brm\s+-rf`, `ls -la`, false}, {`^reboot$`, `id; reboot`, false},
	} {
		got, err := Search(tc.pattern, tc.cmd)
		if err != nil || got != tc.want {
			t.Errorf("%q / %q: %v %v", tc.pattern, tc.cmd, got, err)
		}
	}
	for _, bad := range []string{`[`, ``} {
		if _, err := Search(bad, ""); err == nil {
			t.Fatalf("%q 必须拒绝", bad)
		}
	}
}
