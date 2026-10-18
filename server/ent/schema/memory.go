package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Memory 组内长期记忆：AI 与人积累下来的环境知识（某台主机每天几点跑什么脚本、某个地址是哪台设备、
// 哪类告警在这里是正常的）。每次对话、巡检与研判都会带上，免得每轮都从头查一遍。
// 是背景不是指令；人工写的优先，AI 只能删改自己写的。
type Memory struct {
	ent.Schema
}

func (Memory) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.UUID("group_id", uuid.UUID{}),
		// 关于哪台主机，空表示整个组
		field.UUID("asset_id", uuid.UUID{}).Optional().Nillable(),
		field.Text("content"),
		// ai 由 AI 会话写入 / human 人工写入或改过
		field.String("source"),
		// 人工为用户名，AI 为写入它的会话
		field.String("author"),
		field.UUID("session_id", uuid.UUID{}).Optional().Nillable(),
	}
}

func (Memory) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("group_id", "updated_at"),
	}
}
