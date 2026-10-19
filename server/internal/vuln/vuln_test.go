package vuln

import (
	"testing"
	"time"
)

func TestCompareDeb(t *testing.T) {
	less := [][2]string{
		{"1.0~rc1", "1.0"},
		{"1.0", "1.0-1"},
		{"1.0-1", "1.0-1+deb12u1"},
		{"3.0.11-1~deb12u2", "3.0.11-1"},
		{"2.7.1-2", "2.8.2-1~deb13u1"},
		{"1:10.1.0-11+deb13u2", "1:10.1.0-11+deb13u3"},
		{"9.9", "1:0.1"},
		{"1.2a", "1.2b"},
		{"1.2", "1.2a"},
		{"10.05.1~dfsg-1+deb13u1", "10.05.1~dfsg-1+deb13u3"},
		{"20250101", "202501010000000000000001"},
	}
	for _, p := range less {
		if CompareDeb(p[0], p[1]) >= 0 || CompareDeb(p[1], p[0]) <= 0 {
			t.Errorf("应有 %s < %s", p[0], p[1])
		}
	}
	for _, v := range []string{"1.0-1", "1:2.3~rc1-4+b1", "0:1.0"} {
		if CompareDeb(v, v) != 0 {
			t.Errorf("%s 应等于自身", v)
		}
	}
	if CompareDeb("0:1.0", "1.0") != 0 || CompareDeb("1.01", "1.1") != 0 {
		t.Error("缺省 epoch 为 0、数字段按数值比较")
	}
}

func TestCVSSv3(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
		"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
		"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.6,
	}
	for vec, want := range cases {
		if got, ok := CVSSv3(vec); !ok || got != want {
			t.Errorf("%s: 期望 %.1f，得到 %.1f %v", vec, want, got, ok)
		}
	}
	for _, bad := range []string{"", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "CVSS:3.1/AV:N", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"} {
		if _, ok := CVSSv3(bad); ok {
			t.Errorf("%q 应判为无效", bad)
		}
	}
}

func TestDue(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour
	cases := []struct {
		st   Status
		ok   bool
		want bool
	}{
		{Status{}, false, true},
		{Status{At: now.Add(-time.Hour)}, true, false},
		{Status{At: now.Add(-25 * time.Hour)}, true, true},
		{Status{At: now.Add(-30 * time.Minute), Error: "x"}, true, false},
		{Status{At: now.Add(-61 * time.Minute), Error: "x"}, true, true},
	}
	for i, c := range cases {
		if got := due(c.st, c.ok, day, now); got != c.want {
			t.Errorf("用例 %d：期望 %v，得到 %v", i, c.want, got)
		}
	}
}
