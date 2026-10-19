package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// VulnRecord 漏洞库：OSV 公告按（生态, 源码包）拆开的一行。生态如 Debian:13，包名是源码包。
// 每天从 OSV 同步一次（或读离线目录），同一生态整批替换
type VulnRecord struct {
	ent.Schema
}

// VulnRange 受影响区间：introduced 起（"0" 表示一直），fixed 修复版本，空表示还没修
type VulnRange struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed,omitempty"`
}

func (VulnRecord) Fields() []ent.Field {
	return []ent.Field{
		field.Int("id"),
		field.String("osv_id"),
		field.String("ecosystem"),
		field.String("package"),
		field.JSON("ranges", []VulnRange{}),
		field.Strings("aliases").Optional(),
		field.Text("summary").Optional(),
		// CVSS 3.x 基础分，由向量算出；没有 v3 向量为 0
		field.Float("score").Default(0),
		field.String("vector").Optional(),
		field.Time("published").Optional().Nillable(),
		field.Time("synced_at").Default(time.Now),
	}
}

func (VulnRecord) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("ecosystem", "package"),
	}
}
