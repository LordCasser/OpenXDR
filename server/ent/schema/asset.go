package schema

import (
	"encoding/json"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

func newV7() uuid.UUID { return uuid.Must(uuid.NewV7()) }

// Asset 资产：所有事件挂靠的根实体。
type Asset struct {
	ent.Schema
}

func (Asset) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.String("hostname"),
		field.String("os").Optional().Nillable(),
		field.Strings("ip_addrs").Optional(),
		field.UUID("agent_id", uuid.UUID{}).Optional().Nillable().Unique(),
		field.Time("first_seen").Default(time.Now),
		field.Time("last_seen").Default(time.Now),
		// 采集配置，随 Register 下发给 agent。为空表示用 agent 内置默认
		field.JSON("config", json.RawMessage{}).Optional(),
		// 所属组。未分组的资产只有全局 admin 可见可管
		field.UUID("group_id", uuid.UUID{}).Optional().Nillable(),
		// agent 自报的版本号，注册时更新
		field.String("agent_version").Optional().Nillable(),
		// 失联起始时刻：已发过失联通知，恢复后清空。避免同一次失联反复通知
		field.Time("silent_since").Optional().Nillable(),
	}
}

func (Asset) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("events", Event.Type),
		edge.To("alerts", Alert.Type),
		edge.To("commands", Command.Type),
	}
}
