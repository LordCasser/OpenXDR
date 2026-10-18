package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// AIJob 在请求之外跑的一次模型调用：发起时落一行 running，后台跑完写回结果或错误，
// 前端轮询这一行。换页、刷新、请求落到另一个节点都不丢，长调用也不会被反代超时掐断。
// 只存结果，不存输入（导入文档里有明文凭据，只在内存里交给模型）。
type AIJob struct{ ent.Schema }

func (AIJob) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now).Immutable(),
		// explain 日志解读 / host_import 运维文档提取
		field.String("kind"),
		// 解读的是哪条日志、导入到哪个组；同一对象的最新一次就是它的当前结果
		field.String("subject"),
		// 发起人：导入结果只给发起人看
		field.String("owner"),
		// 解读的语言等影响结果的参数
		field.String("variant").Default(""),
		// running / done / failed
		field.String("status").Default("running"),
		field.JSON("result", map[string]any{}).Optional(),
		field.String("error").Default(""),
		field.Time("finished_at").Optional().Nillable(),
	}
}

func (AIJob) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("kind", "subject", "variant", "created_at"),
		index.Fields("created_at"),
	}
}
