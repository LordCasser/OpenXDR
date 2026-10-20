package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"time"
)

// Report 保留原始 Markdown；渲染与外发由报告模块处理。
type Report struct{ ent.Schema }

func (Report) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.UUID("session_id", uuid.UUID{}),
		field.UUID("group_id", uuid.UUID{}),
		field.String("title").MaxLen(200),
		field.Text("markdown"),
		// ok 无需处理（只存档不推送）/ attention 有需要人处理的事项 / urgent 需要立即处理
		field.String("level").Default("attention"),
		// 一句话结论：列表、通知与报告页头都用它，旧报告为空
		field.String("summary").Default(""),
	}
}
func (Report) Indexes() []ent.Index {
	return []ent.Index{index.Fields("group_id", "created_at"), index.Fields("session_id")}
}

// ReportRead 谁看过哪份报告：按人记，一个人看过不影响别人的未读
type ReportRead struct{ ent.Schema }

func (ReportRead) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.UUID("report_id", uuid.UUID{}),
		field.UUID("user_id", uuid.UUID{}),
		field.Time("read_at").Default(time.Now),
	}
}
func (ReportRead) Indexes() []ent.Index {
	return []ent.Index{index.Fields("report_id", "user_id").Unique(), index.Fields("user_id")}
}
