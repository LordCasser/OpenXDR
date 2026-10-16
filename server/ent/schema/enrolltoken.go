package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// EnrollToken 主机接入令牌：持有者可把主机接入指定组。有效期内可重复使用，便于批量装机。
type EnrollToken struct {
	ent.Schema
}

func (EnrollToken) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		// 只存 SHA-256，明文只在创建时返回一次
		field.String("token_hash").Unique().Sensitive(),
		field.UUID("group_id", uuid.UUID{}),
		field.String("created_by"),
		field.Time("created_at").Default(time.Now),
		field.Time("expires_at"),
		field.Bool("revoked").Default(false),
		// 已接入的主机数
		field.Int("uses").Default(0),
	}
}

func (EnrollToken) Indexes() []ent.Index {
	return []ent.Index{index.Fields("group_id")}
}
