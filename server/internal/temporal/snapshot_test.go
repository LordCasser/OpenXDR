package temporal

import (
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
	matches, err := old.Evaluate([]Event{event(1, 0, "base"), event(2, 1, "base")})
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
				_, err := snapshot.Evaluate([]Event{event(1, 0, "base"), event(2, 1, "base")})
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
