package temporal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	dir        string // 实际读取的时序规则目录，仅用于日志
}

func (s *Snapshot) Revision() string         { return s.revision }
func (s *Snapshot) Dir() string              { return s.dir }
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
// 两个路径都先解析成实际目录再整批读取：TEMPORAL_RULES_PATH 指向符号链接（current → v-<版本>）时，
// 切换链接即原子发布，同一次加载不会混读新旧目录。符号链接发布的版本目录必须带 SHA256SUMS 清单，
// 清单与目录内规则文件逐一核对，半写入或被原地改动的目录整批拒绝。
func LoadSnapshot(baseDir, temporalDir string) (*Snapshot, error) {
	baseDir, err := filepath.EvalSymlinks(baseDir)
	if err != nil {
		return nil, err
	}
	base, err := sigma.LoadDirStrict(baseDir)
	if err != nil {
		return nil, err
	}
	link, err := os.Lstat(temporalDir)
	if err != nil {
		return nil, err
	}
	dir, err := filepath.EvalSymlinks(temporalDir)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("时序规则路径不是目录")
	}
	manifest, err := readManifest(dir)
	if err != nil {
		return nil, err
	}
	if manifest == nil && link.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s 经符号链接发布，版本目录缺少 %s 清单，可能尚未写完", temporalDir, manifestName)
	}
	references := map[string]bool{}
	for _, r := range base.Rules() {
		references[r.ID] = true
	}
	snapshot := &Snapshot{base: base, referenced: map[string]bool{}, dir: dir}
	digests := map[string]string{}
	sources := map[string]string{}
	listed := 0
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
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
		if manifest != nil {
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			want, ok := manifest[filepath.ToSlash(rel)]
			if !ok || want != fmt.Sprintf("%x", sha256.Sum256(data)) {
				return fmt.Errorf("%s: 与 %s 清单不符，版本目录未写完或被改动", path, manifestName)
			}
			listed++
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
	if manifest != nil && listed != len(manifest) {
		return nil, fmt.Errorf("%s 清单列出的规则文件有缺失，版本目录未写完", manifestName)
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

const manifestName = "SHA256SUMS"

// readManifest 读取 sha256sum 格式清单（"<十六进制摘要>  <相对路径>"），不存在时返回 nil。
// 清单只能列 .yml/.yaml；格式不对、重复或列了其他文件都拒绝，免得清单本身也是半写入。
func readManifest(dir string) (map[string]string, error) {
	data, err := os.ReadFile(filepath.Join(dir, manifestName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	manifest := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		digest, name, ok := strings.Cut(line, "  ")
		name = strings.TrimPrefix(name, "./")
		ext := filepath.Ext(name)
		if decoded, err := hex.DecodeString(digest); !ok || err != nil || len(decoded) != sha256.Size || (ext != ".yml" && ext != ".yaml") {
			return nil, fmt.Errorf("%s 格式无效: %q", manifestName, line)
		}
		if _, dup := manifest[name]; dup {
			return nil, fmt.Errorf("%s 重复列出 %s", manifestName, name)
		}
		manifest[name] = strings.ToLower(digest)
	}
	return manifest, nil
}
