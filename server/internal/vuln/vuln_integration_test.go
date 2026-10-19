//go:build integration

package vuln

import (
	"archive/zip"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/internal/assetmap"
	"openxdr/server/internal/testdb"
)

func writeZip(t *testing.T, path string, recs map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	for name, body := range recs {
		w, _ := z.Create(name + ".json")
		w.Write([]byte(body))
	}
	z.Close()
	f.Close()
}

const rec = `{"id":"%s","summary":"%s","aliases":["%s"],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
"affected":[{"package":{"name":"%s","ecosystem":"%s"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}%s]}]}]}`

func TestSyncAndMatch(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	sw := assetmap.Software{OS: "debian", Version: "13", Manager: "dpkg", Packages: [][4]string{
		{"openssh-server", "1:10.0p1-7", "openssh", "1:10.0p1-7"},
		{"openssh-client", "1:10.0p1-7", "openssh", "1:10.0p1-7"},
		{"libssl3t64", "3.5.1-1", "openssl", "3.5.1-1"},
		{"bash", "5.2.37-2", "bash", "5.2.37-2"},
	}}
	b, _ := json.Marshal(sw)
	client.Asset.Create().SetHostname("h").SetSoftware(b).ExecX(ctx)

	dir := t.TempDir()
	sprintf := func(id, summary, alias, pkg, eco, fixed string) string {
		ev := ""
		if fixed != "" {
			ev = `,{"fixed":"` + fixed + `"}`
		}
		return sprintfRec(id, summary, alias, pkg, eco, ev)
	}
	writeZip(t, filepath.Join(dir, "Debian.zip"), map[string]string{
		"a": sprintf("DEBIAN-CVE-1", "ssh 修了", "CVE-1", "openssh", "Debian:13", "1:10.0p1-7+deb13u1"),
		"b": sprintf("DEBIAN-CVE-2", "ssl 没修", "CVE-2", "openssl", "Debian:13", ""),
		"c": sprintf("DEBIAN-CVE-3", "bash 早修了", "CVE-3", "bash", "Debian:13", "5.0-1"),
		"d": sprintf("DEBIAN-CVE-4", "别的版本", "CVE-4", "openssh", "Debian:12", "1:9.2p1-2+deb12u9"),
		"e": `{"id":"DEBIAN-CVE-5","withdrawn":"2024-01-01T00:00:00Z","affected":[{"package":{"name":"bash","ecosystem":"Debian:13"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`,
		"f": `not json`,
	})
	s := &Syncer{DB: client, SQL: db, Dir: dir, Interval: 0}
	if err := s.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if n := client.VulnRecord.Query().CountX(ctx); n != 3 {
		t.Fatalf("只应入库 Debian:13 的三条（撤回与坏条目跳过），得到 %d", n)
	}
	if st := LoadStatus(ctx, client)["Debian:13"]; st.Records != 3 || st.Error != "" {
		t.Fatalf("同步状态不对: %+v", st)
	}

	listening := []assetmap.Listener{{Proto: "tcp", Addr: "0.0.0.0", Port: 22, Package: "openssh-server"}}
	rep, err := Match(ctx, db, &sw, listening)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Fixable) != 1 || rep.Fixable[0].Source != "openssh" || !rep.Fixable[0].Exposed || rep.Fixable[0].FixedIn != "1:10.0p1-7+deb13u1" || rep.Fixable[0].MaxScore != 9.8 || len(rep.Fixable[0].Binaries) != 2 {
		t.Fatalf("可修复的应是暴露在外的 openssh: %+v", rep.Fixable)
	}
	if len(rep.Unfixed) != 1 || rep.Unfixed[0].Source != "openssl" || rep.Unfixed[0].Exposed {
		t.Fatalf("暂无修复的应是 openssl: %+v", rep.Unfixed)
	}

	// 再同步一次：整批替换，不叠加
	writeZip(t, filepath.Join(dir, "Debian.zip"), map[string]string{"a": sprintf("DEBIAN-CVE-1", "ssh 修了", "CVE-1", "openssh", "Debian:13", "1:10.0p1-7+deb13u1")})
	if err := s.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if n := client.VulnRecord.Query().CountX(ctx); n != 1 {
		t.Fatalf("再同步应整批替换，得到 %d", n)
	}
	// 离线目录缺包：记错误、旧数据不动
	os.Remove(filepath.Join(dir, "Debian.zip"))
	if err := s.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if st := LoadStatus(ctx, client)["Debian:13"]; st.Error == "" || st.Records != 1 || client.VulnRecord.Query().CountX(ctx) != 1 {
		t.Fatalf("同步失败应记错误并保留旧数据: %+v", st)
	}
}

func sprintfRec(id, summary, alias, pkg, eco, ev string) string {
	return fmt.Sprintf(rec, id, summary, alias, pkg, eco, ev)
}
