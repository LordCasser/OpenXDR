package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Group 资产组：纳管与授权的单位。几十台主机一组，用户按组获得角色。
type Group struct {
	ent.Schema
}

func (Group) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.String("name").Unique(),
	}
}

// GroupMember 用户在某个组内的角色。全局 admin 不需要成员记录，天然管所有组。
type GroupMember struct {
	ent.Schema
}

func (GroupMember) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.UUID("group_id", uuid.UUID{}),
		field.UUID("user_id", uuid.UUID{}),
		// admin / analyst / viewer，与全局角色同一套取值
		field.String("role"),
	}
}

func (GroupMember) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("group_id", "user_id").Unique(),
		index.Fields("user_id"),
	}
}
