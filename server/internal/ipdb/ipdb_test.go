package ipdb

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testdata 里的库由 testdata/gen 生成：203.0.113.0/25 → AS64500、198.51.100.0/24 → AS64501（无国家）、
// 2001:db8:1::/48 → AS64502 JP、10.0.0.0/8 → AS64999、8.8.8.0/24 → AS64510 US（探测地址）；国家库 203.0.113.0/24 → AU
func TestLookup(t *testing.T) {
	d := &DB{Dir: "testdata"}
	d.Refresh()
	defer d.Close()
	if !d.Ready() {
		t.Fatal("测试库没加载")
	}
	cases := []struct {
		ip   string
		want Info
	}{
		{"203.0.113.0", Info{64500, "Example Net A", "AU"}},
		// 区间边界：ASN 只到 /25 末尾，国家库覆盖整个 /24
		{"203.0.113.127", Info{64500, "Example Net A", "AU"}},
		{"203.0.113.128", Info{Country: "AU"}},
		{"203.0.112.255", Info{}},
		{"198.51.100.255", Info{ASN: 64501, Org: "Example Net B"}},
		{"2001:db8:1::1", Info{64502, "Example Net V6", "JP"}},
		{"2001:db8:1:ffff:ffff:ffff:ffff:ffff", Info{64502, "Example Net V6", "JP"}},
		{"2001:db8:2::1", Info{}},
		// IPv4 映射成 IPv6 的写法按 IPv4 查
		{"::ffff:203.0.113.5", Info{64500, "Example Net A", "AU"}},
	}
	for _, c := range cases {
		if got := d.Lookup(netip.MustParseAddr(c.ip)); got != c.want {
			t.Errorf("%s: 得到 %+v，期望 %+v", c.ip, got, c.want)
		}
	}
}

// 库缺失：查不到也不出错，Ready 为假；放进文件后下一次 Refresh 自动加载
func TestMissingThenReload(t *testing.T) {
	dir := t.TempDir()
	d := &DB{Dir: dir}
	d.Refresh()
	defer d.Close()
	ip := netip.MustParseAddr("203.0.113.1")
	if d.Ready() || d.Lookup(ip) != (Info{}) {
		t.Fatal("空目录不该有数据")
	}
	copyFile(t, filepath.Join("testdata", CountryFile), filepath.Join(dir, CountryFile))
	d.Refresh()
	if got := d.Lookup(ip); !d.Ready() || got != (Info{Country: "AU"}) {
		t.Fatalf("只有国家库时应只填国家: %+v", got)
	}
	// 放反的文件不加载，原来的继续用
	copyFile(t, filepath.Join("testdata", ASNFile), filepath.Join(dir, CountryFile+".tmp"))
	if err := os.Rename(filepath.Join(dir, CountryFile+".tmp"), filepath.Join(dir, CountryFile)); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	_ = os.Chtimes(filepath.Join(dir, CountryFile), future, future)
	d.Refresh()
	if got := d.Lookup(ip); got != (Info{Country: "AU"}) {
		t.Fatalf("放反的库不该替换原来的: %+v", got)
	}
	var nilDB *DB
	if nilDB.Ready() || nilDB.Lookup(ip) != (Info{}) {
		t.Fatal("nil 库应等同缺失")
	}
	(&DB{}).Refresh()
}

func TestValidate(t *testing.T) {
	if err := Validate(filepath.Join("testdata", ASNFile), "ASN"); err != nil {
		t.Fatalf("测试库应通过: %v", err)
	}
	if err := Validate(filepath.Join("testdata", ASNFile), "Country"); err == nil {
		t.Fatal("类型不符应拒绝")
	}
	bad := filepath.Join(t.TempDir(), "bad.mmdb")
	_ = os.WriteFile(bad, []byte("<html>404</html>"), 0o644)
	if err := Validate(bad, "ASN"); err == nil {
		t.Fatal("不是 mmdb 应拒绝")
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
