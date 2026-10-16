package schema

import (
	"encoding/json"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// Setting 控制台可改的运行时配置，按键存 JSON。未写过的键用环境变量给的默认值。
type Setting struct {
	ent.Schema
}

func (Setting) Fields() []ent.Field {
	return []ent.Field{
		// 配置键，如 notify
		field.String("id").Immutable(),
		field.JSON("value", json.RawMessage{}),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}
