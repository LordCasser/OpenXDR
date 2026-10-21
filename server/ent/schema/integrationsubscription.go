package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"time"
)

// SubscriptionPeriod 保存启用区间，暂停期间的新事件不补发。
type SubscriptionPeriod struct {
	From time.Time  `json:"from"`
	To   *time.Time `json:"to,omitempty"`
}

// SubscriptionConfig 固定每个版本的发生时间范围与目标，未分发积压也保留旧目标。
type SubscriptionConfig struct {
	From     time.Time  `json:"from"`
	To       *time.Time `json:"to,omitempty"`
	URL      string     `json:"url"`
	Version  int64      `json:"version"`
	GroupIDs []string   `json:"groupIds"`
	Kinds    []string   `json:"kinds"`
	Secret   []byte     `json:"secret"`
	KeyID    string     `json:"keyId"`
}

type IntegrationSubscription struct{ ent.Schema }

func (IntegrationSubscription) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7), field.UUID("integration_id", uuid.UUID{}),
		field.String("name").MaxLen(100), field.String("url").MaxLen(2048), field.Int64("version").Default(1),
		field.Strings("group_ids"), field.Strings("kinds"), field.Bool("enabled").Default(false),
		field.JSON("periods", []SubscriptionPeriod{}), field.Time("created_at").Default(time.Now),
		field.Bytes("secret").Sensitive(), field.String("key_id"),
		field.JSON("configurations", []SubscriptionConfig{}).Optional().Sensitive(),
		field.Bool("deleted").Default(false),
	}
}
func (IntegrationSubscription) Indexes() []ent.Index {
	return []ent.Index{index.Fields("integration_id")}
}

type IntegrationDelivery struct{ ent.Schema }

func (IntegrationDelivery) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7), field.UUID("subscription_id", uuid.UUID{}), field.UUID("event_id", uuid.UUID{}),
		field.String("status").Default("pending"), field.Time("created_at").Default(time.Now), field.Time("retry_window_at").Default(time.Now), field.Time("next_at").Default(time.Now),
		field.Time("lease_until").Optional().Nillable(), field.Int64("lease_generation").Default(0), field.Int("attempts").Default(0),
		field.String("target_url"), field.Int64("target_version"), field.Bytes("secret").Sensitive(), field.String("key_id"),
		field.String("last_error").Default(""), field.Time("completed_at").Optional().Nillable(),
	}
}
func (IntegrationDelivery) Indexes() []ent.Index {
	return []ent.Index{index.Fields("subscription_id", "event_id").Unique(), index.Fields("status", "next_at")}
}

type IntegrationAttempt struct{ ent.Schema }

func (IntegrationAttempt) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7), field.UUID("delivery_id", uuid.UUID{}),
		field.Time("started_at"), field.Time("ended_at"), field.Int("http_status").Default(0), field.String("result"), field.Int64("lease_generation"),
	}
}
func (IntegrationAttempt) Indexes() []ent.Index {
	return []ent.Index{index.Fields("delivery_id", "started_at")}
}
