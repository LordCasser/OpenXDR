package schema

import (
	"encoding/json"
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"time"
)

// IntegrationEvent 事务发件箱；载荷不可变，投递进度另存。
type IntegrationEvent struct{ ent.Schema }

func (IntegrationEvent) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.UUID("incident_id", uuid.UUID{}), field.Int64("revision"),
		field.String("kind"), field.Time("occurred_at").Default(time.Now),
		field.Strings("group_ids"), field.JSON("payload", json.RawMessage{}),
		field.Bool("dispatched").Default(false),
	}
}
func (IntegrationEvent) Indexes() []ent.Index {
	return []ent.Index{index.Fields("incident_id", "revision").Unique(), index.Fields("dispatched", "occurred_at")}
}
