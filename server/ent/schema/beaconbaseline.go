package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// BeaconBaseline 外联心跳基线：某资产上见过的周期外联（容器、进程、端口、域名或地址）。
// 首次入表即「新出现的心跳」，之后同一组合不再触发。监控、NTP 这类基础设施本来就很规律，
// 只看规律会被它们淹没；能区分 C2 的是这条规律外联是不是新冒出来的
type BeaconBaseline struct {
	ent.Schema
}

func (BeaconBaseline) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.UUID("asset_id", uuid.UUID{}),
		field.String("flow"),
		field.Time("first_seen"),
	}
}

func (BeaconBaseline) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("asset_id", "flow").Unique(),
	}
}
