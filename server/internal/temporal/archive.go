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
