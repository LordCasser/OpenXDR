package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// HostCredential 资产的纳管凭据；只存密文，不进入资产接口、模型查询视图或会话。
type HostCredential struct{ ent.Schema }

func (HostCredential) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.UUID("asset_id", uuid.UUID{}).Unique(),
		field.UUID("group_id", uuid.UUID{}),
		field.String("address"),
		field.Int("port").Default(22),
		field.String("username"),
		field.String("kind"),
		field.String("host_key").Default(""),
		field.Bytes("sealed").Sensitive(),
		field.Time("created_at").Default(time.Now),
		field.Time("lease_until").Default(func() time.Time { return time.Unix(0, 0) }),
	}
}
func (HostCredential) Indexes() []ent.Index { return []ent.Index{index.Fields("group_id")} }
