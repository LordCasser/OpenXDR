package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Command 响应指令。这是系统里唯一能对被监控主机造成实际影响的东西，
// 每一条都要留下完整审计：谁下的、对谁、做了什么、结果如何。
type Command struct {
	ent.Schema
}

func (Command) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.String("kind"),
		// pending 待下发 / sent 已下发待回执 / unknown 投递或执行结果未知 / succeeded / failed / unsupported
		field.String("status").Default("pending"),
		field.UUID("asset_id", uuid.UUID{}),
		field.UUID("incident_id", uuid.UUID{}).Optional().Nillable(),
		field.UUID("process_guid", uuid.UUID{}).Optional().Nillable(),
		field.Uint32("pid").Default(0),
		field.JSON("allow_endpoints", []string{}).Optional(),
		field.String("issued_by").Default("api"),
		field.String("detail").Optional().Nillable(),
		// 以下仅 exec 使用：下发的命令行与 agent 回传的执行输出
		field.Text("cmd").Optional().Nillable(),
		field.Uint32("timeout_ms").Default(0),
		field.Int32("exit_code").Optional().Nillable(),
		field.Text("stdout").Optional().Nillable(),
		field.Text("stderr").Optional().Nillable(),
		field.Bool("truncated").Default(false),
		field.Time("completed_at").Optional().Nillable(),
	}
}

func (Command) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("asset", Asset.Type).Ref("commands").Field("asset_id").Unique().Required(),
	}
}

func (Command) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("asset_id", "status"),
		index.Fields("created_at"),
	}
}
