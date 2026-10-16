// Package schedule 预设任务调度：仓库 tasks/*.yml 定义任务，到点按组拉起 Pi 会话。
package schedule

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/robfig/cron/v3"
	"gopkg.in/yaml.v3"

	"openxdr/server/ent"
	enttask "openxdr/server/ent/task"
)

// Spec 任务 YAML 的结构。
type Spec struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"name"`
	Schedule string `yaml:"schedule"`
	Model    string `yaml:"model"`
	Targets  struct {
		Group string `yaml:"group"`
	} `yaml:"targets"`
	ApprovalTimeout string `yaml:"approval_timeout"`
	Prompt          string `yaml:"prompt"`

	approvalTimeout time.Duration
}

// ParseSchedule 五段 cron，支持 @daily 等描述符与 CRON_TZ= 前缀。
func ParseSchedule(s string) (cron.Schedule, error) { return cron.ParseStandard(s) }

func parseSpec(data []byte) (Spec, error) {
	var s Spec
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // 拼错的字段直接拒绝，不能静默变成默认值
	if err := dec.Decode(&s); err != nil {
		return s, err
	}
	switch {
	case s.ID == "":
		return s, errors.New("id 必填")
	case s.Prompt == "":
		return s, errors.New("prompt 必填")
	}
	if _, err := ParseSchedule(s.Schedule); err != nil {
		return s, fmt.Errorf("schedule 无效: %w", err)
	}
	if s.Name == "" {
		s.Name = s.ID
	}
	if s.Targets.Group == "" {
		s.Targets.Group = "*"
	}
	s.approvalTimeout = 10 * time.Minute
	if s.ApprovalTimeout != "" {
		d, err := time.ParseDuration(s.ApprovalTimeout)
		if err != nil || d <= 0 {
			return s, fmt.Errorf("approval_timeout 无效: %q", s.ApprovalTimeout)
		}
		s.approvalTimeout = d
	}
	return s, nil
}

// LoadDir 读目录下全部 *.yml / *.yaml。坏文件跳过并记日志：坏任务不跑，不拖累好任务。
func LoadDir(dir string) []Spec {
	files, _ := filepath.Glob(filepath.Join(dir, "*.yml"))
	more, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
	var specs []Spec
	seen := map[string]string{}
	for _, f := range append(files, more...) {
		data, err := os.ReadFile(f)
		if err == nil {
			var s Spec
			if s, err = parseSpec(data); err == nil {
				if prev, dup := seen[s.ID]; dup {
					err = fmt.Errorf("id %q 与 %s 重复", s.ID, prev)
				} else {
					seen[s.ID] = f
					specs = append(specs, s)
					continue
				}
			}
		}
		slog.Error("任务文件无效，已跳过", "file", f, "err", err)
	}
	return specs
}

// Sync 把 YAML 定义同步进库。启停与自定义周期归界面，不覆盖；
// YAML 里消失的任务标记 removed，停止调度但保留运行历史。
func Sync(ctx context.Context, db *ent.Client, specs []Spec) error {
	ids := make([]string, len(specs))
	for i, s := range specs {
		ids[i] = s.ID
		timeout := int64(s.approvalTimeout / time.Second)
		err := db.Task.UpdateOneID(s.ID).
			SetName(s.Name).SetSchedule(s.Schedule).SetModel(s.Model).
			SetTargetGroup(s.Targets.Group).SetPrompt(s.Prompt).
			SetApprovalTimeoutSeconds(timeout).SetRemoved(false).
			Exec(ctx)
		if ent.IsNotFound(err) {
			err = db.Task.Create().
				SetID(s.ID).SetName(s.Name).SetSchedule(s.Schedule).SetModel(s.Model).
				SetTargetGroup(s.Targets.Group).SetPrompt(s.Prompt).
				SetApprovalTimeoutSeconds(timeout).
				Exec(ctx)
		}
		if err != nil {
			return err
		}
	}
	return db.Task.Update().Where(enttask.IDNotIn(ids...), enttask.Removed(false)).SetRemoved(true).Exec(ctx)
}
