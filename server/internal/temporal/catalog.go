package temporal

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"openxdr/server/internal/sigma"
)

var _ sigma.Catalog = (*Store)(nil)

func (s *Store) Evaluate(class int, os string, raw map[string]any) []*sigma.Rule {
	if current := s.Current(); current != nil {
		return current.EvaluateBase(class, os, raw)
	}
	return nil
}
func (s *Store) Rules() []*sigma.Rule {
	current := s.Current()
	if current == nil {
		return nil
	}
	var out []*sigma.Rule
	for _, r := range current.base.Rules() {
		copy := *r
		copy.Tactics = append([]string(nil), r.Tactics...)
		copy.Techniques = append([]string(nil), r.Techniques...)
		out = append(out, &copy)
	}
	for _, r := range current.rules {
		out = append(out, &sigma.Rule{ID: r.id, Title: r.title, Author: r.author, Severity: r.severity, Kind: r.kind, WindowSeconds: int(r.window / time.Second), Threshold: r.threshold, References: append([]string(nil), r.references...)})
	}
	return out
}
func (s *Store) TitleOf(id string) string {
	current := s.Current()
	if current == nil {
		return ""
	}
	for _, r := range current.rules {
		if r.id == id {
			return r.title
		}
	}
	return current.base.TitleOf(id)
}
func (s *Store) AuthorOf(id string) string {
	current := s.Current()
	if current == nil {
		return ""
	}
	for _, r := range current.rules {
		if r.id == id {
			return r.author
		}
	}
	return current.base.AuthorOf(id)
}

// Watch 整体重载；任意失败保留旧快照并记错误，不分开更新基础规则。
func (s *Store) Watch(ctx context.Context, baseDir, temporalDir string, interval time.Duration) {
	if interval <= 0 {
		return
	}
	timer := time.NewTicker(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			before := s.Current()
			if err := s.Reload(baseDir, temporalDir); err != nil {
				slog.Error("时序规则重载失败，保留旧快照", "err", err)
				continue
			}
			after := s.Current()
			if before == nil || before.Revision() != after.Revision() {
				slog.Info("检测规则快照已更新", "revision", after.Revision(), "dir", after.Dir())
			}
		}
	}
}

// PruneLoop 定期清理过期候选，必须经 cluster.RunLeader 运行以保证集群单活。
// 每轮取一次当前快照，按其最大窗口清理；删满一批就继续，直到清完。
func (s *Store) PruneLoop(ctx context.Context, db *sql.DB, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		current := s.Current()
		if current == nil {
			continue
		}
		var total int64
		for {
			n, err := PruneCandidates(ctx, db, current.Revision(), current.MaxWindow())
			total += n
			if err != nil {
				slog.Error("清理过期时序候选失败", "err", err)
				break
			}
			if n < 10000 {
				break
			}
		}
		if total > 0 {
			slog.Info("清理过期时序候选", "deleted", total)
		}
	}
}
