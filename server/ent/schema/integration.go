package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"time"
)

// Integration 外部系统身份，不继承负责人用户权限。
type Integration struct{ ent.Schema }

func (Integration) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.String("name").MaxLen(100), field.String("purpose").MaxLen(1000),
		field.UUID("owner_id", uuid.UUID{}), field.Bool("enabled").Default(false),
		field.Strings("scopes"), field.Int64("permission_version").Default(1),
		field.Bool("resolution_enabled").Default(false), field.Strings("allowed_resolutions").Optional(),
		field.Bool("allow_malicious_false_positive").Default(false),
		field.Time("created_at").Default(time.Now),
	}
}

// IntegrationGroup 授权组；空集合没有任何资源权限。
type IntegrationGroup struct{ ent.Schema }

func (IntegrationGroup) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7), field.UUID("integration_id", uuid.UUID{}), field.UUID("group_id", uuid.UUID{}),
	}
}
func (IntegrationGroup) Indexes() []ent.Index {
	return []ent.Index{index.Fields("integration_id", "group_id").Unique()}
}

// IntegrationToken 令牌只存摘要，明文仅创建时返回。
type IntegrationToken struct{ ent.Schema }

func (IntegrationToken) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7), field.UUID("integration_id", uuid.UUID{}),
		field.String("token_hash").Unique().Sensitive(), field.String("prefix"), field.Strings("scopes"),
		field.Time("created_at").Default(time.Now), field.Time("expires_at"), field.Bool("revoked").Default(false),
		field.Time("last_used_at").Optional().Nillable(), field.String("last_remote_addr").Optional(),
	}
}
func (IntegrationToken) Indexes() []ent.Index { return []ent.Index{index.Fields("integration_id")} }
