package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// AIUsage 平台自己发起的模型调用（事件研判、资产标注）一次一行，供用量概览。
// AI 助手与定时任务的用量随会话消息落库，不在这里重复记。
type AIUsage struct{ ent.Schema }

func (AIUsage) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("ts").Default(time.Now),
		// triage / annotate
		field.String("feature"),
		field.String("model"),
		field.Int("input"),
		field.Int("output"),
	}
}

func (AIUsage) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("ts"),
	}
}
