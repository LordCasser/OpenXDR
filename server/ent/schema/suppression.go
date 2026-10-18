package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Suppression 误报抑制规则。分析师判定某条检测规则在某台主机（或全局）上
// 是噪声后，后续命中不再产生告警。
//
// 抑制永远不是静默的：命中次数持续累加，界面上看得见被压掉了多少，
// 避免一条抑制规则悄悄把真实攻击也吃掉。
type Suppression struct {
	ent.Schema
}

func (Suppression) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.String("rule_id"),
		// 为空表示对所有资产生效
		field.UUID("asset_id", uuid.UUID{}).Optional().Nillable(),
		field.String("reason").Optional().Nillable(),
		field.String("created_by").Default("api"),
		// 为空表示长期有效；到期后自动失效，避免抑制规则无限积累
		field.Time("expires_at").Optional().Nillable(),
		field.Int("matched_count").Default(0),
		field.Time("last_matched_at").Optional().Nillable(),
		// active 生效 / proposed AI 提议、等组管理员批准 / rejected 被拒绝。只有 active 进抑制索引
		field.String("status").Default("active"),
		// 字段条件（AND）：只压掉事件体里这些字段对得上的命中，比如只压某个域名、某条命令行。
		// 为空表示整条规则都压——范围大，AI 的提议不允许为空
		field.JSON("conditions", []SuppressCondition{}).Optional(),
		// 提议它的 AI 会话
		field.UUID("session_id", uuid.UUID{}).Optional().Nillable(),
		field.String("reviewed_by").Optional().Nillable(),
		field.Time("reviewed_at").Optional().Nillable(),
	}
}

// SuppressCondition 一条字段条件：事件体的 dot path 取值与 value 比较，不区分大小写
type SuppressCondition struct {
	Field string `json:"field"`
	// equals / contains / endswith
	Op    string `json:"op"`
	Value string `json:"value"`
}

func (Suppression) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("rule_id"),
	}
}
