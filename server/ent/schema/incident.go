package schema

import (
	"encoding/json"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// Incident 事件：关联引擎聚合出的攻击故事，AI 研判的对象。
// 状态机：open → triaged →（新证据）→ open → triaged；closed / false_positive 是分析师终态。
type Incident struct {
	ent.Schema
}

func (Incident) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.String("status").Default("open"),
		field.JSON("graph", json.RawMessage{}),
		field.JSON("ai_verdict", json.RawMessage{}).Optional(),
		field.String("title").Optional().Nillable(),
		// webhook 投递标记：非空表示已推送（或按策略静默跳过），空则待投递
		field.Time("notified_at").Optional().Nillable(),
		// 结案：closed 表示属实已处置，false_positive 表示误报或良性；备注会作为案例喂回研判
		field.Text("resolution").Optional().Nillable(),
		field.String("resolved_by").Optional().Nillable(),
		field.Time("resolved_at").Optional().Nillable(),
		// AI 的结案建议：人在事件页一键采纳（结案仍记在人名下、照常作为人工案例回喂研判）或忽略。
		// 任何状态变更都会清掉它
		field.JSON("closure_proposal", &ClosureProposal{}).Optional(),
	}
}

// ClosureProposal AI 提的结案建议
type ClosureProposal struct {
	// closed 属实已处置 / false_positive 误报或良性
	Status    string     `json:"status"`
	Note      string     `json:"note"`
	SessionID uuid.UUID  `json:"sessionId"`
	ReportID  *uuid.UUID `json:"reportId,omitempty"`
	At        time.Time  `json:"at"`
}

func (Incident) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("alerts", Alert.Type),
	}
}
