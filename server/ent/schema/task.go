package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Task 预设定时任务。定义来自仓库 tasks/*.yml，启动与热重载时同步进来；
// 启停与自定义周期归界面所有，同步不覆盖。
type Task struct {
	ent.Schema
}

func (Task) Fields() []ent.Field {
	return []ent.Field{
		// YAML 里的 id，如 daily-host-inspection
		field.String("id").Immutable(),
		field.String("name"),
		// 五段 cron，来自 YAML
		field.String("schedule"),
		// 界面改过的周期，优先于 schedule
		field.String("custom_schedule").Optional().Nillable(),
		field.Bool("enabled").Default(true),
		// 为空用平台默认模型
		field.String("model").Default(""),
		// 组选择器："*" 表示每个组各跑一次，否则为组名
		field.String("target_group").Default("*"),
		field.Int64("approval_timeout_seconds").Default(600),
		field.Text("prompt"),
		// YAML 里已删掉的任务不再调度，但保留历史
		field.Bool("removed").Default(false),
	}
}

// TaskRun 任务在某个组上的一次运行，对应一个 Pi 会话。
type TaskRun struct {
	ent.Schema
}

func (TaskRun) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.String("task_id"),
		field.UUID("group_id", uuid.UUID{}),
		field.UUID("session_id", uuid.UUID{}).Optional().Nillable(),
		field.Time("started_at").Default(time.Now),
		field.Time("finished_at").Optional().Nillable(),
		// running / succeeded / failed
		field.String("status").Default("running"),
		field.Text("error").Optional().Nillable(),
	}
}

func (TaskRun) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("task_id", "started_at"),
		index.Fields("status"),
	}
}
