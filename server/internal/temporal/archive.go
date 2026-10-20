package temporal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"openxdr/server/internal/sigma"
)

type archiveDocument struct {
	Format   int               `json:"format"`
	Revision string            `json:"revision"`
	Base     map[string]string `json:"base"`
	Temporal map[string]string `json:"temporal"`
}

// Archive 原文属于规则配置，不经公开规则列表接口分发。
func (s *Snapshot) Archive() []byte { return append([]byte(nil), s.archive...) }

// RestoreArchive 重新编译并核对内容哈希，损坏或不支持的归档不能伪装为原版本。
func RestoreArchive(data []byte) (*Snapshot, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var doc archiveDocument
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("归档包含尾随内容")
	}
	if doc.Format != 1 || doc.Base == nil || doc.Temporal == nil {
		return nil, fmt.Errorf("不支持或不完整的规则归档")
	}
	base, err := sigma.CompileSources(doc.Base)
	if err != nil {
		return nil, err
	}
	snapshot := &Snapshot{base: base, referenced: map[string]bool{}}
	references := map[string]bool{}
	for id := range doc.Base {
		references[id] = true
	}
	for id, source := range doc.Temporal {
		rule, err := Compile([]byte(source), references)
		if err != nil {
			return nil, err
		}
		if rule.id != id {
			return nil, fmt.Errorf("归档时序规则 ID 不符: %s", id)
		}
		snapshot.rules = append(snapshot.rules, rule)
		for _, ref := range rule.references {
			snapshot.referenced[ref] = true
		}
		if rule.window > snapshot.window {
			snapshot.window = rule.window
		}
	}
	sort.Slice(snapshot.rules, func(i, j int) bool { return snapshot.rules[i].id < snapshot.rules[j].id })
	h := sha256.New()
	fmt.Fprintln(h, base.Revision())
	for _, rule := range snapshot.rules {
		fmt.Fprintf(h, "%d:%s:%x\n", len(rule.id), rule.id, sha256.Sum256([]byte(doc.Temporal[rule.id])))
	}
	snapshot.revision = fmt.Sprintf("%x", h.Sum(nil))
	if snapshot.revision != doc.Revision {
		return nil, fmt.Errorf("规则归档哈希不符")
	}
	snapshot.archive = append([]byte(nil), data...)
	return snapshot, nil
}

// ArchivedRule 是归档中一条时序规则的原文与元数据，以及它引用的基础规则原文，供历史规则查询展示。
type ArchivedRule struct {
	ID            string            `json:"id"`
	Title         string            `json:"title"`
	Author        string            `json:"author,omitempty"`
	Kind          string            `json:"kind"`
	GroupBy       string            `json:"groupBy"`
	Severity      int16             `json:"severity"`
	WindowSeconds int               `json:"windowSeconds"`
	Threshold     int               `json:"threshold,omitempty"`
	MinAssets     int               `json:"minAssets"`
	References    []string          `json:"references"`
	Source        string            `json:"source"`
	Base          map[string]string `json:"base"`
}

// ViewArchive 解出归档中的时序规则，按 ID 排序。它按原文重算内容哈希并核对文档与库中版本，
// 被改动的归档拒绝展示；只编译时序规则（引用集合取归档基础规则 ID），不编译基础规则，
// 因此展示不受基础规则引擎后续语义变化影响，也不代表能在当前引擎下重现结果（那是 RestoreArchive 的职责）。
func ViewArchive(data []byte, revision string) ([]ArchivedRule, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var doc archiveDocument
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}
	if doc.Format != 1 || doc.Base == nil || doc.Temporal == nil {
		return nil, fmt.Errorf("不支持或不完整的规则归档")
	}
	if doc.Revision != revision || contentRevision(doc) != revision {
		return nil, fmt.Errorf("规则归档哈希不符")
	}
	references := map[string]bool{}
	for id := range doc.Base {
		references[id] = true
	}
	rules := make([]ArchivedRule, 0, len(doc.Temporal))
	for id, source := range doc.Temporal {
		rule, err := Compile([]byte(source), references)
		if err != nil {
			return nil, fmt.Errorf("归档时序规则 %s: %w", id, err)
		}
		if rule.id != id {
			return nil, fmt.Errorf("归档时序规则 ID 不符: %s", id)
		}
		base := map[string]string{}
		for _, ref := range rule.references {
			base[ref] = doc.Base[ref]
		}
		rules = append(rules, ArchivedRule{ID: rule.id, Title: rule.title, Author: rule.author, Kind: rule.kind, GroupBy: rule.groupBy,
			Severity: rule.severity, WindowSeconds: int(rule.window / time.Second), Threshold: rule.threshold, MinAssets: rule.minAssets,
			References: append([]string(nil), rule.references...), Source: source, Base: base})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules, nil
}

// contentRevision 按 LoadSnapshot 的版本算法只用原文重算版本哈希（基础规则部分同 sigma.Engine.Revision）。
func contentRevision(doc archiveDocument) string {
	entries := make([]string, 0, len(doc.Base))
	for id, source := range doc.Base {
		entries = append(entries, fmt.Sprintf("%d:%s:%x", len(id), id, sha256.Sum256([]byte(source))))
	}
	sort.Strings(entries)
	h := sha256.New()
	for _, entry := range entries {
		fmt.Fprintln(h, entry)
	}
	base := fmt.Sprintf("%x", h.Sum(nil))
	ids := make([]string, 0, len(doc.Temporal))
	for id := range doc.Temporal {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	h = sha256.New()
	fmt.Fprintln(h, base)
	for _, id := range ids {
		fmt.Fprintf(h, "%d:%s:%x\n", len(id), id, sha256.Sum256([]byte(doc.Temporal[id])))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (s *Snapshot) persistArchive(ctx context.Context, tx *sql.Tx) error {
	var revision string
	err := tx.QueryRowContext(ctx, `SELECT revision FROM temporal_rule_snapshots WHERE revision=$1 FOR KEY SHARE`, s.revision).Scan(&revision)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO temporal_rule_snapshots(revision,document) VALUES($1,$2::jsonb) ON CONFLICT DO NOTHING`, s.revision, string(s.archive))
	return err
}

// PruneArchives 只删除无引用的旧规则原文，限批且跳过正在被入库事务锁定的版本。
func PruneArchives(ctx context.Context, db *sql.DB, cutoff time.Time) (int64, error) {
	result, err := db.ExecContext(ctx, `WITH expired AS (
 SELECT s.revision FROM temporal_rule_snapshots s WHERE s.created_at < $1
 AND NOT EXISTS(SELECT 1 FROM temporal_candidates c WHERE c.revision=s.revision)
 AND NOT EXISTS(SELECT 1 FROM temporal_detections d WHERE d.revision=s.revision)
 AND NOT EXISTS(SELECT 1 FROM temporal_evaluation_gaps g WHERE g.revision=s.revision)
 ORDER BY s.created_at,s.revision LIMIT 1000 FOR UPDATE OF s SKIP LOCKED)
 DELETE FROM temporal_rule_snapshots s USING expired e WHERE s.revision=e.revision`, cutoff)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
