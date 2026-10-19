package temporal

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"time"

	"openxdr/server/internal/sigma"
)

// Snapshot 私有持有基础引擎，调用者不能只热更新其中一半。
type Snapshot struct {
	base       *sigma.Engine
	referenced map[string]bool
	rules      []*Rule
	revision   string
	window     time.Duration
	archive    []byte
}

func (s *Snapshot) Revision() string         { return s.revision }
func (s *Snapshot) MaxWindow() time.Duration { return s.window }
func (s *Snapshot) EvaluateBase(class int, os string, raw map[string]any) []*sigma.Rule {
	hits := s.base.Evaluate(class, os, raw)
	out := make([]*sigma.Rule, 0, len(hits))
	for _, hit := range hits {
		copy := *hit
		copy.Tactics = append([]string(nil), hit.Tactics...)
		copy.Techniques = append([]string(nil), hit.Techniques...)
		out = append(out, &copy)
	}
	return out
}
func (s *Snapshot) Evaluate(events []Event) ([]Match, error) {
	var result []Match
	for _, rule := range s.rules {
		matches, err := rule.Evaluate(events)
		if err != nil {
			return nil, err
		}
		for i := range matches {
			matches[i].Revision = s.revision
		}
		result = append(result, matches...)
	}
	return result, nil
}

// LoadSnapshot 只读取每份文件一次，版本使用实际参与编译的原文。
// 发布者应以不可变版本目录提供文件，禁止把原地逐文件写入当作原子发布。
func LoadSnapshot(baseDir, temporalDir string) (*Snapshot, error) {
	base, err := sigma.LoadDirStrict(baseDir)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(temporalDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("时序规则路径不是目录")
	}
	references := map[string]bool{}
	for _, r := range base.Rules() {
		references[r.ID] = true
	}
	snapshot := &Snapshot{base: base, referenced: map[string]bool{}}
	digests := map[string]string{}
	sources := map[string]string{}
	err = filepath.WalkDir(temporalDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if ext := filepath.Ext(path); ext != ".yml" && ext != ".yaml" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rule, err := Compile(data, references)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if _, ok := digests[rule.id]; ok {
			return fmt.Errorf("时序规则 ID 重复: %s", rule.id)
		}
		sources[rule.id] = string(data)
		digests[rule.id] = fmt.Sprintf("%x", sha256.Sum256(data))
		snapshot.rules = append(snapshot.rules, rule)
		for _, id := range rule.references {
			snapshot.referenced[id] = true
		}
		if rule.window > snapshot.window {
			snapshot.window = rule.window
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(snapshot.rules, func(i, j int) bool { return snapshot.rules[i].id < snapshot.rules[j].id })
	h := sha256.New()
	fmt.Fprintln(h, base.Revision())
	for _, r := range snapshot.rules {
		fmt.Fprintf(h, "%d:%s:%s\n", len(r.id), r.id, digests[r.id])
	}
	snapshot.revision = fmt.Sprintf("%x", h.Sum(nil))
	snapshot.archive, err = json.Marshal(archiveDocument{Format: 1, Revision: snapshot.revision, Base: base.Sources(), Temporal: sources})
	if err != nil {
		return nil, err
	}
	return snapshot, nil
}

type Store struct{ current atomic.Pointer[Snapshot] }

func (s *Store) Current() *Snapshot { return s.current.Load() }

// Reload 失败不覆盖已有快照；处理一条事件时只取一次 Current。
func (s *Store) Reload(baseDir, temporalDir string) error {
	next, err := LoadSnapshot(baseDir, temporalDir)
	if err != nil {
		return err
	}
	if current := s.Current(); current != nil && current.Revision() == next.Revision() {
		return nil
	}
	s.current.Store(next)
	return nil
}

// CandidateRules 只保留时序规则实际引用的命中；其他基础告警照常处理。
func (s *Snapshot) CandidateRules(hits []*sigma.Rule) []string {
	var ids []string
	for _, hit := range hits {
		if s.referenced[hit.ID] {
			ids = append(ids, hit.ID)
		}
	}
	return ids
}
