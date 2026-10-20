package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// IPInfo 公网目的地址的背景信息：反向解析、离线 IP 库与 VirusTotal 查询结果的缓存。
// 只是给人和 AI 认地址用的参考，不参与检测；过期后后台重查。
type IPInfo struct{ ent.Schema }

func (IPInfo) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.String("ip"),
		// 反向解析（PTR）得到的主机名，查不到为空
		field.String("ptr").Default(""),
		field.Time("ptr_at").Optional().Nillable(),
		// 以下来自 VirusTotal，未配置 VT_API_KEY 或还没查过时 vt_at 为空
		field.String("as_owner").Default(""),
		field.Int("asn").Default(0),
		field.String("country").Default(""),
		field.Int("malicious").Default(0),
		field.Int("suspicious").Default(0),
		// 历史上解析到这个地址的域名，最多几条
		field.Strings("domains").Optional(),
		field.Time("vt_at").Optional().Nillable(),
		// 以下来自本地离线库（DB-IP Lite，IPDB_DIR），不向外发地址；库缺失或还没查过时 ipdb_at 为空。
		// 与上面 VirusTotal 的同类字段分开存，两边各按各的到期重查，互不覆盖
		field.Int("ipdb_asn").Default(0),
		field.String("ipdb_org").Default(""),
		// ISO 3166 两位国家代码，地理定位结果（不是 AS 注册地）
		field.String("ipdb_country").Default(""),
		field.Time("ipdb_at").Optional().Nillable(),
	}
}

func (IPInfo) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("ip").Unique(),
	}
}
