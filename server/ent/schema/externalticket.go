package schema

import (
	"encoding/json"
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"time"
)

type ExternalTicket struct{ ent.Schema }

func (ExternalTicket) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7), field.UUID("integration_id", uuid.UUID{}), field.UUID("incident_id", uuid.UUID{}),
		field.String("external_id").MaxLen(200), field.String("url").MaxLen(2048), field.String("status").MaxLen(100), field.String("title").MaxLen(500),
		field.Time("updated_at").Default(time.Now), field.Bool("source_deleted").Default(false),
	}
}
func (ExternalTicket) Indexes() []ent.Index {
	return []ent.Index{index.Fields("integration_id", "external_id").Unique(), index.Fields("incident_id")}
}

type IntegrationIdempotency struct{ ent.Schema }

func (IntegrationIdempotency) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7), field.UUID("integration_id", uuid.UUID{}),
		field.String("method"), field.String("path").MaxLen(1024), field.String("key").MaxLen(200), field.String("request_hash"),
		field.Int("status"), field.JSON("response", json.RawMessage{}), field.Time("expires_at"),
	}
}
func (IntegrationIdempotency) Indexes() []ent.Index {
	return []ent.Index{index.Fields("integration_id", "method", "path", "key").Unique(), index.Fields("expires_at")}
}
