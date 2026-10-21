package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// TrustedSource 运维自动化来源：运维脚本、第三方 AI 运维插件这类日常自动化的 SSH 登录身份。
// 平台按登录规律与告警结论自动识别（origin=auto），组管理员也可以手工登记（origin=manual）。
// agent 给登录会话里的进程打上 login_session（sshd 认证日志里的用户、来源地址、公钥指纹，按审计会话号关联），
// 对得上的告警照常入库，但挂到来源上、不进关联与研判；凭据窃取、日志清除这类高危例外仍进研判。
//
// 识别只认登录事实，不认命令行与进程名——那些攻击者可以随意构造。
// 与抑制同一套治理：按组生效、必须有有效期、可撤销、命中持续计数、增删都落审计。
type TrustedSource struct {
	ent.Schema
}

func (TrustedSource) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.UUID("group_id", uuid.UUID{}),
		field.String("name").NotEmpty(),
		field.String("reason").Optional().Nillable(),
		field.String("created_by"),
		// 必填：可信来源是降低检测的配置，不允许长期有效
		field.Time("expires_at"),
		// 以下条件全部满足才算命中，至少要有公钥指纹或来源网段之一
		// SSH 公钥指纹（SHA256:…，与 ssh-keygen -lf 同一写法）
		field.String("key_fingerprint").Optional().Nillable(),
		// 登录来源网段（CIDR，单个地址写 /32 或 /128）
		field.String("source_cidr").Optional().Nillable(),
		// 登录用户名
		field.String("login_user").Optional().Nillable(),
		field.Int("matched_count").Default(0),
		field.Time("last_matched_at").Optional().Nillable(),
		// 撤销后保留记录：已挂在它上面的告警还要说得清来源
		field.Time("revoked_at").Optional().Nillable(),
		field.String("revoked_by").Optional().Nillable(),
		// manual 人工登记 / auto 平台自动识别
		field.String("origin").Default("manual"),
		// 固定：自动逻辑不再续期、改条件或让它过期；被判恶意时的自动停用仍然生效
		field.Bool("pinned").Default(false),
		// 自动识别的依据，每次复核刷新（固定后不再刷新）
		field.JSON("evidence", &AutomationEvidence{}).Optional(),
		// 待发的通知：identified 自动识别生效 / revoked 自动停用；发出后清空，失败下轮重试
		field.String("notice").Optional().Nillable(),
		// 系统停用的原因：verdict 来源的告警被判属实、恶意或可疑；人停用的为空
		field.String("revoke_cause").Optional().Nillable(),
		// 导致系统停用的事件
		field.UUID("revoke_incident_id", uuid.UUID{}).Optional().Nillable(),
		// 人最近一次启用的时刻：此前告警上的结论不再触发自动停用（人已经看过并决定继续信任）
		field.Time("confirmed_at").Optional().Nillable(),
		// 删除只是隐藏：已挂上的告警还要说得清来源，自动识别也要记得这个身份被人否决过
		field.Time("deleted_at").Optional().Nillable(),
		field.String("deleted_by").Optional().Nillable(),
	}
}

// AutomationEvidence 自动识别的依据：窗口内的登录统计与告警结论统计
type AutomationEvidence struct {
	WindowDays int       `json:"windowDays"`
	Days       int       `json:"days"`
	Logins     int       `json:"logins"`
	Hosts      int       `json:"hosts"`
	Addresses  []string  `json:"addresses"`
	LastLogin  time.Time `json:"lastLogin"`
	// 触发告警的事件里，人工判误报、AI 判良性的各有几个
	HumanBenign int       `json:"humanBenign"`
	AIBenign    int       `json:"aiBenign"`
	Alerts      int       `json:"alerts"`
	CheckedAt   time.Time `json:"checkedAt"`
}

func (TrustedSource) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("group_id"),
		// 同一个登录身份在组内只有一条自动识别记录：停用、删除过的也留着，免得被自动加回
		index.Fields("group_id", "key_fingerprint", "login_user").Unique().Annotations(entsql.IndexWhere("origin = 'auto'")),
	}
}
