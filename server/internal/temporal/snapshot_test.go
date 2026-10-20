package temporal

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const baseFixture = `id: base
 title: placeholder
`
const validBase = `id: base
title: Test base
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains: old-marker
  condition: selection
`
const validTemporal = `id: repeated
kind: event_count
within: 1m
rules: [base]
threshold: 2
`

func writeRule(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}
func fixture(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	seq := t.TempDir()
	writeRule(t, filepath.Join(base, "base.yml"), validBase)
	writeRule(t, filepath.Join(seq, "count.yml"), validTemporal)
	return base, seq
}

func TestSnapshotContentRevisionAndAtomicReload(t *testing.T) {
	base, seq := fixture(t)
	var store Store
	if err := store.Reload(base, seq); err != nil {
		t.Fatal(err)
	}
	old := store.Current()
	// 同内容换目录，版本不变。
	copyBase, copySeq := fixture(t)
	copied, err := LoadSnapshot(copyBase, copySeq)
	if err != nil {
		t.Fatal(err)
	}
	if copied.Revision() != old.Revision() {
		t.Fatal("路径不应改变规则版本")
	}
	writeRule(t, filepath.Join(base, "base.yml"), strings.ReplaceAll(validBase, "old-marker", "new-marker"))
	if err := store.Reload(base, seq); err != nil {
		t.Fatal(err)
	}
	next := store.Current()
	if next.Revision() == old.Revision() {
		t.Fatal("基础规则修改必须改变整个快照版本")
	}
	raw := map[string]any{"process": map[string]any{"cmd_line": "old-marker"}}
	if len(old.EvaluateBase(1007, "linux", raw)) != 1 || len(next.EvaluateBase(1007, "linux", raw)) != 0 {
		t.Fatal("已取得的旧快照必须保持原条件")
	}
	// 返回的元数据不能被调用者用于篡改已发布快照。
	hits := old.EvaluateBase(1007, "linux", raw)
	hits[0].Product = "windows"
	if len(old.EvaluateBase(1007, "linux", raw)) != 1 {
		t.Fatal("调用者修改了快照内容")
	}
	// 时序规则坏掉不能让更新到一半的基础规则成为当前快照。
	writeRule(t, filepath.Join(seq, "count.yml"), strings.ReplaceAll(validTemporal, "[base]", "[missing]"))
	writeRule(t, filepath.Join(base, "base.yml"), validBase)
	if err := store.Reload(base, seq); err == nil {
		t.Fatal("未知引用必须失败")
	}
	if store.Current() != next {
		t.Fatal("失败重载替换了有效快照")
	}
	matches, err := old.Evaluate(GroupByAsset, []Event{event(1, 0, "base"), event(2, 1, "base")})
	if err != nil || len(matches) != 1 || matches[0].Revision != old.Revision() {
		t.Fatalf("命中未绑定版本: %+v %v", matches, err)
	}
}

func TestSnapshotRejectsDuplicatesAndUnreadableDirectory(t *testing.T) {
	for _, which := range []string{"base", "temporal"} {
		base, seq := fixture(t)
		if which == "base" {
			writeRule(t, filepath.Join(base, "duplicate.yml"), validBase)
		} else {
			writeRule(t, filepath.Join(seq, "duplicate.yml"), validTemporal)
		}
		if _, err := LoadSnapshot(base, seq); err == nil {
			t.Fatalf("%s 重复 ID 必须拒绝", which)
		}
	}
	base, seq := fixture(t)
	if _, err := LoadSnapshot(filepath.Join(base, "missing"), seq); err == nil {
		t.Fatal("缺失目录必须拒绝")
	}
	writeRule(t, filepath.Join(base, "broken.yml"), baseFixture)
	if _, err := LoadSnapshot(base, seq); err == nil {
		t.Fatal("基础规则加载失败不能跳过")
	}
}

func TestSnapshotConcurrentReaders(t *testing.T) {
	base, seq := fixture(t)
	var store Store
	if err := store.Reload(base, seq); err != nil {
		t.Fatal(err)
	}
	var readers sync.WaitGroup
	for range 8 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for range 100 {
				snapshot := store.Current()
				if snapshot == nil || len(snapshot.Revision()) != 64 {
					t.Error("半成品快照")
				}
				_, err := snapshot.Evaluate(GroupByAsset, []Event{event(1, 0, "base"), event(2, 1, "base")})
				if err != nil {
					t.Error(err)
				}
			}
		}()
	}
	for range 10 {
		if err := store.Reload(base, seq); err != nil {
			t.Fatal(err)
		}
	}
	readers.Wait()
}

// 版本目录写完后补 SHA256SUMS，再用 rename 原子替换 current 链接。
func publishVersion(t *testing.T, root, name string, files map[string]string, manifest bool) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	var sums strings.Builder
	for file, body := range files {
		writeRule(t, filepath.Join(dir, file), body)
		fmt.Fprintf(&sums, "%x  %s\n", sha256.Sum256([]byte(body)), file)
	}
	if manifest {
		writeRule(t, filepath.Join(dir, "SHA256SUMS"), sums.String())
	}
	return dir
}

func switchLink(t *testing.T, root, target string) {
	t.Helper()
	tmp := filepath.Join(root, "current.tmp")
	if err := os.Symlink(target, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
}

func TestSymlinkVersionDirectoryRelease(t *testing.T) {
	base, _ := fixture(t)
	root := t.TempDir()
	current := filepath.Join(root, "current")
	second := strings.ReplaceAll(validTemporal, "threshold: 2", "threshold: 3")
	publishVersion(t, root, "v-1", map[string]string{"count.yml": validTemporal}, true)
	publishVersion(t, root, "v-2", map[string]string{"count.yml": second}, true)
	switchLink(t, root, "v-1")
	var store Store
	if err := store.Reload(base, current); err != nil {
		t.Fatal(err)
	}
	first := store.Current()
	if len(first.rules) != 1 || first.rules[0].threshold != 2 || filepath.Base(first.Dir()) != "v-1" {
		t.Fatalf("链接未解析到 v-1: %+v", first.rules)
	}
	switchLink(t, root, "v-2")
	if err := store.Reload(base, current); err != nil {
		t.Fatal(err)
	}
	released := store.Current()
	if released.Revision() == first.Revision() || released.rules[0].threshold != 3 || filepath.Base(released.Dir()) != "v-2" {
		t.Fatal("切换链接未发布新版本")
	}
	// 半写入：缺清单、清单列的文件还没写、文件内容与清单不符、多出未列文件，都整批拒绝并保留 v-2。
	more := strings.ReplaceAll(validTemporal, "id: repeated", "id: more")
	sums := fmt.Sprintf("%x  count.yml\n%x  more.yml\n", sha256.Sum256([]byte(validTemporal)), sha256.Sum256([]byte(more)))
	cases := []struct {
		name   string
		damage func(dir string)
	}{
		{"缺清单", func(string) {}},
		{"文件未写完", func(dir string) {
			writeRule(t, filepath.Join(dir, "SHA256SUMS"), sums)
			if err := os.Remove(filepath.Join(dir, "more.yml")); err != nil {
				t.Fatal(err)
			}
		}},
		{"内容被改", func(dir string) {
			writeRule(t, filepath.Join(dir, "SHA256SUMS"), sums)
			writeRule(t, filepath.Join(dir, "more.yml"), more+"# 改动\n")
		}},
		{"未列文件", func(dir string) {
			writeRule(t, filepath.Join(dir, "SHA256SUMS"), fmt.Sprintf("%x  count.yml\n", sha256.Sum256([]byte(validTemporal))))
		}},
		{"清单格式错", func(dir string) {
			writeRule(t, filepath.Join(dir, "SHA256SUMS"), "not-a-digest  count.yml\n")
		}},
	}
	for i, tc := range cases {
		version := fmt.Sprintf("v-broken-%d", i)
		tc.damage(publishVersion(t, root, version, map[string]string{"count.yml": validTemporal, "more.yml": more}, false))
		switchLink(t, root, version)
		if err := store.Reload(base, current); err == nil {
			t.Fatalf("%s: 半写入目录必须拒绝", tc.name)
		}
		if store.Current() != released {
			t.Fatalf("%s: 失败重载替换了有效快照", tc.name)
		}
	}
	// 首次加载就指向半写入目录时不能产生快照，调用方据此拒绝启动。
	var fresh Store
	if err := fresh.Reload(base, current); err == nil || fresh.Current() != nil {
		t.Fatal("首次加载半写入目录必须失败")
	}
	// 普通目录不强制清单，保持原有用法；版本不依赖路径。
	plain := t.TempDir()
	writeRule(t, filepath.Join(plain, "count.yml"), validTemporal)
	if snapshot, err := LoadSnapshot(base, plain); err != nil || snapshot.Revision() != first.Revision() {
		t.Fatalf("普通目录加载失败或版本依赖路径: %v", err)
	}
	// 基础规则目录也经符号链接时同样解析一次再读。
	baseLink := filepath.Join(root, "base-current")
	if err := os.Symlink(base, baseLink); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := LoadSnapshot(baseLink, plain); err != nil || snapshot.Revision() != first.Revision() {
		t.Fatalf("基础规则链接未解析: %v", err)
	}
}
