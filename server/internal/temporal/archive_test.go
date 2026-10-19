package temporal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestArchiveRestoresOldRulesAfterFilesChange(t *testing.T) {
	base, seq := fixture(t)
	original, err := LoadSnapshot(base, seq)
	if err != nil {
		t.Fatal(err)
	}
	data := original.Archive()
	writeRule(t, filepath.Join(base, "base.yml"), strings.ReplaceAll(validBase, "old-marker", "new-marker"))
	if err := os.RemoveAll(seq); err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreArchive(data)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Revision() != original.Revision() {
		t.Fatal("恢复后版本改变")
	}
	raw := map[string]any{"process": map[string]any{"cmd_line": "old-marker"}}
	if len(restored.EvaluateBase(1007, "linux", raw)) != 1 {
		t.Fatal("恢复依赖了当前文件而非归档")
	}
	events := []Event{event(1, 0, "base"), event(2, 1, "base")}
	want, err := original.Evaluate(events)
	if err != nil {
		t.Fatal(err)
	}
	got, err := restored.Evaluate(events)
	if err != nil || !reflect.DeepEqual(want, got) {
		t.Fatalf("恢复改变检测结果: %+v %+v %v", want, got, err)
	}
	data[0] = '!'
	if _, err := RestoreArchive(original.Archive()); err != nil {
		t.Fatalf("返回内容允许外部修改内部归档: %v", err)
	}
}

func TestArchiveRejectsTampering(t *testing.T) {
	base, seq := fixture(t)
	snapshot, err := LoadSnapshot(base, seq)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*archiveDocument){
		func(d *archiveDocument) { d.Format = 99 },
		func(d *archiveDocument) { d.Base["base"] = strings.ReplaceAll(d.Base["base"], "old-marker", "changed") },
		func(d *archiveDocument) {
			d.Temporal["repeated"] = strings.ReplaceAll(d.Temporal["repeated"], "threshold: 2", "threshold: 3")
		},
		func(d *archiveDocument) { d.Revision = "invalid" },
		func(d *archiveDocument) { d.Base = nil },
	} {
		var doc archiveDocument
		if err := json.Unmarshal(snapshot.Archive(), &doc); err != nil {
			t.Fatal(err)
		}
		mutate(&doc)
		data, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := RestoreArchive(data); err == nil {
			t.Fatal("损坏归档必须拒绝")
		}
	}
	if _, err := RestoreArchive(append(snapshot.Archive(), []byte(" {}")...)); err == nil {
		t.Fatal("尾随文档必须拒绝")
	}
}
