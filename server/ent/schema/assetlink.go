package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// AssetLink 从网络事件聚合出的依赖边：谁（哪个进程）连了哪个地址的哪个端口。
// 对端属于哪台资产在读取时按 IP 解析——发现的机器之后纳管了，图谱自动连上。
type AssetLink struct{ ent.Schema }

func (AssetLink) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.String("src_ip"),
		// agent 上报的连接带资产归属；sensor 看到的没有，读取时按 src_ip 解析
		field.UUID("src_asset_id", uuid.UUID{}).Optional().Nillable(),
		field.String("dst_ip"),
		field.Int("dst_port"),
		field.String("proto"),
		// 发起连接的进程名，取不到为空串
		field.String("process").Default(""),
		field.Int64("count"),
		field.Time("first_seen"),
		field.Time("last_seen"),
	}
}

func (AssetLink) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("src_ip", "dst_ip", "dst_port", "proto", "process").Unique(),
		index.Fields("src_asset_id"),
		index.Fields("dst_ip"),
		index.Fields("last_seen"),
	}
}
