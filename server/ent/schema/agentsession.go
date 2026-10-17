package schema

import (
	"encoding/json"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// AgentSession 一次 Pi 会话：一段对话，或一次定时任务运行。会话绑定一个组，
// 只能触达组内资产；发起人决定权限（定时任务为 system）。
type AgentSession struct {
	ent.Schema
}

func (AgentSession) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		// chat 对话 / task 定时任务
		field.String("kind"),
		field.UUID("group_id", uuid.UUID{}),
		// 发起人用户名；定时任务为 system
		field.String("initiator"),
		field.String("model"),
		field.String("title").Optional().Nillable(),
		// running / idle（对话等待下一轮）/ succeeded / failed
		field.String("status").Default("running"),
		field.Text("error").Optional().Nillable(),
		field.Time("finished_at").Optional().Nillable(),
		// 固定执行期限加清理宽限；过期后只标失败，不重放命令。
		field.Time("run_expires_at").Optional().Nillable(),
		// 从事件或待办「交给 AI」时绑定的对象：incident:<id> / finding:<id>，同组、最多 10 个
		field.Strings("subjects").Optional(),
	}
}

func (AgentSession) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("group_id", "created_at"),
		index.Fields("initiator"),
		index.Fields("status", "run_expires_at"),
	}
}

// SessionMessage 会话消息。content 原样存 Pi 的消息对象（含工具调用与结果），
// 下一轮原样喂回，历史不做有损转换。
type SessionMessage struct {
	ent.Schema
}

func (SessionMessage) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.UUID("session_id", uuid.UUID{}),
		field.Int("seq"),
		// user / assistant / toolResult，冗余出来便于前端过滤
		field.String("role"),
		field.JSON("content", json.RawMessage{}),
	}
}

func (SessionMessage) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("session_id", "seq").Unique(),
	}
}
