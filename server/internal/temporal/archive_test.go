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
	want, err := original.Evaluate(GroupByAsset, events)
	if err != nil {
		t.Fatal(err)
	}
	got, err := restored.Evaluate(GroupByAsset, events)
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
		if _, err := ViewArchive(data, snapshot.Revision()); err == nil {
			t.Fatal("损坏归档不能用于展示历史规则")
		}
	}
	if _, err := RestoreArchive(append(snapshot.Archive(), []byte(" {}")...)); err == nil {
		t.Fatal("尾随文档必须拒绝")
	}
}

// 历史规则展示只靠原文重算版本，必须与加载时的版本算法一致（用仓库全量规则校验）。
func TestViewArchiveMatchesLoadedRevision(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	snapshot, err := LoadSnapshot(filepath.Join(root, "rules"), filepath.Join(root, "temporal-rules"))
	if err != nil {
		t.Fatal(err)
	}
	rules, err := ViewArchive(snapshot.Archive(), snapshot.Revision())
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != len(snapshot.rules) {
		t.Fatalf("归档时序规则数 %d", len(rules))
	}
	for i, r := range rules {
		// 序列允许同一基础规则出现在多个步骤，原文按 ID 只存一份
		distinct := map[string]bool{}
		for _, ref := range snapshot.rules[i].references {
			distinct[ref] = true
		}
		if r.ID != snapshot.rules[i].id || r.Source == "" || len(r.Base) != len(distinct) {
			t.Fatalf("归档规则元数据或引用原文不完整: %+v", r)
		}
		for _, ref := range r.References {
			if !strings.Contains(r.Base[ref], ref) {
				t.Fatalf("%s 缺少基础规则 %s 原文", r.ID, ref)
			}
		}
		if r.ID == "temporal:linux-account-auth-burst" && (r.GroupBy != GroupByAccount || r.WindowSeconds != 600 || r.Threshold != 5 || r.MinAssets != 2) {
			t.Fatalf("账号规则元数据错误: %+v", r)
		}
	}
	if _, err := ViewArchive(snapshot.Archive(), strings.Repeat("0", 64)); err == nil {
		t.Fatal("库中版本与归档不符必须拒绝")
	}
}
