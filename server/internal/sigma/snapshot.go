package sigma

import (
	"crypto/sha256"
	"fmt"
	"os"
	"sort"
)

// LoadDirStrict 为跨事件规则构造完整基础快照。任一加载失败或重复 ID 都拒绝整批，
// 避免引用的基础条件消失而时序规则仍在继续工作。
func LoadDirStrict(dir string) (*Engine, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("规则路径不是目录: %s", dir)
	}
	state, report := loadState(dir)
	if len(report.Skipped) > 0 {
		return nil, fmt.Errorf("基础规则加载失败: %v", report.Skipped)
	}
	seen := map[string]bool{}
	for _, rule := range state.rules {
		if seen[rule.ID] {
			return nil, fmt.Errorf("基础规则 ID 重复: %s", rule.ID)
		}
		seen[rule.ID] = true
	}
	engine := &Engine{}
	engine.state.Store(state)
	return engine, nil
}

// Revision 哈希来自实际编译的内容，与目录位置及枚举顺序无关。
func (e *Engine) Revision() string {
	var entries []string
	for _, r := range e.load().rules {
		entries = append(entries, fmt.Sprintf("%d:%s:%s", len(r.ID), r.ID, r.digest))
	}
	sort.Strings(entries)
	h := sha256.New()
	for _, entry := range entries {
		fmt.Fprintln(h, entry)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Sources 返回实际参与编译的原文副本，供持久规则版本归档。
func (e *Engine) Sources() map[string]string {
	result := map[string]string{}
	for _, rule := range e.load().rules {
		result[rule.ID] = rule.source
	}
	return result
}

// CompileSources 从归档恢复基础快照，键必须与原文 ID 一致。
func CompileSources(sources map[string]string) (*Engine, error) {
	state := &engineState{byID: map[string]*Rule{}}
	ids := make([]string, 0, len(sources))
	for id := range sources {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		rule, err := Compile([]byte(sources[id]))
		if err != nil {
			return nil, err
		}
		if rule.ID != id {
			return nil, fmt.Errorf("归档基础规则 ID 不符: %s", id)
		}
		state.rules = append(state.rules, rule)
		state.byID[id] = rule
	}
	state.index()
	engine := &Engine{}
	engine.state.Store(state)
	return engine, nil
}
