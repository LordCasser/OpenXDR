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

func TestSpellings(t *testing.T) {
	has := func(list []string, s string) bool {
		for _, v := range list {
			if v == s {
				return true
			}
		}
		return false
	}
	for _, cmd := range []string{"df -hT", "/usr/bin/df -hT", "/bin/df -hT", "/sbin/df -hT"} {
		got := spellings(cmd)
		if !has(got, "df -hT") || !has(got, "/usr/bin/df -hT") || !has(got, "/usr/sbin/df -hT") {
			t.Errorf("%q 的等价写法不全：%v", cmd, got)
		}
	}
	for _, cmd := range []string{"/opt/x/df -hT", "./df", "/usr/bin/../../tmp/df", ""} {
		if got := spellings(cmd); len(got) != 1 || got[0] != cmd {
			t.Errorf("%q 只能原样匹配：%v", cmd, got)
		}
	}
}
