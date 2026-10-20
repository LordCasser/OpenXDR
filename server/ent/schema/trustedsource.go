package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// TrustedSource 可信自动化来源：组管理员登记的运维自动化（运维脚本、第三方 AI 运维插件）的 SSH 登录身份。
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
	}
}

func (TrustedSource) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("group_id"),
	}
}
