package commandgate

import "testing"

func TestFullCommandMatch(t *testing.T) {
	for _, tc := range []struct {
		pattern, cmd string
		want         bool
	}{
		{`whoami`, `whoami`, true}, {`whoami`, `whoami; id`, false}, {`whoami`, `echo x; whoami`, false},
		{`whoami`, `whoami\n`, false}, {`systemctl status [a-z-]+`, `systemctl status ssh`, true},
		{`systemctl status [a-z-]+`, `systemctl status ssh && id`, false},
	} {
		got, err := Match(tc.pattern, tc.cmd)
		if err != nil || got != tc.want {
			t.Errorf("%q / %q: %v %v", tc.pattern, tc.cmd, got, err)
		}
	}
	if _, err := Match(`[`, ""); err == nil {
		t.Fatal("坏正则必须拒绝")
	}
}
