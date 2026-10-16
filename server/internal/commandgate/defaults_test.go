package commandgate

import (
	"regexp"
	"testing"
)

// 默认名单逐条按字面放行，改一个参数就不再匹配。
func TestDefaultAllowIsLiteral(t *testing.T) {
	for _, cmd := range DefaultAIAllow {
		pattern := regexp.QuoteMeta(cmd)
		if ok, err := Match(pattern, cmd); err != nil || !ok {
			t.Errorf("%q 应匹配自身：%v", cmd, err)
		}
		if ok, _ := Match(pattern, cmd+"; rm -rf /"); ok {
			t.Errorf("%q 不应放行拼接命令", cmd)
		}
		if got := display(pattern); got != cmd {
			t.Errorf("display 应还原字面命令 %q，实际 %q", cmd, got)
		}
	}
}

func TestDisplay(t *testing.T) {
	cases := map[string]string{
		`^/usr/bin/df -hT$`:   "/usr/bin/df -hT",
		`^/usr/bin/uname -r$`: "/usr/bin/uname -r",
		`cat /var/log/.*`:     "正则：cat /var/log/.*",
	}
	for in, want := range cases {
		if got := display(in); got != want {
			t.Errorf("display(%q) = %q, want %q", in, got, want)
		}
	}
}
