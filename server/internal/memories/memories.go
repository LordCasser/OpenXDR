// Package memories 组内长期记忆的读取与校验：对话、巡检与研判共用同一份口径。
package memories

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/memory"
)

// Max 每组记忆上限：满了要先删过时的，逼着记忆保持精炼
const Max = 200

// MaxRunes 一条记忆的长度上限
const MaxRunes = 500

// ReviewAfter AI 记忆多久没复核就标成待复核：环境会变，AI 的结论不能一直当真。人工记忆不受影响
const ReviewAfter = 30 * 24 * time.Hour

// negative 否定性结论：做不到、查不了、没有工具这一类。它们最容易变成永久盲区——信了就不会再试，
// 装了新工具或换个办法也发现不了，所以 AI 写的这类记忆不论新旧都标出来，让模型每轮先廉价地重试。
// 宽一点无妨：误标只是多跑一两条只读命令
var negative = regexp.MustCompile(`(?i)无法|不能(?:用|访问|连|查|看|执行|登录|读|获取)|不了|[看查找拿连读搜测做]不到|不支持|不可用|未安装|没装|没有安装|未找到|` +
	`(?:无|没有|缺少?)[^，。；;,\n]{0,16}?(?:工具|命令|权限|途径|办法|手段|客户端|CLI)|` +
	`cannot|can't|unable|not (?:installed|available|found|supported|accessible)|no (?:such|tool|access|permission)|command not found|permission denied`)

// Review 记忆该不该先复核再用：人工写的不标；AI 写的否定性结论总是标，其余过了 ReviewAfter 才标。返回给模型看的说明，空串表示不用
func Review(source, content string, updated, now time.Time) string {
	switch {
	case source != "ai":
		return ""
	case negative.MatchString(content):
		return "否定性结论（做不到/查不了/没有工具），可能已过时：别照信，先用一两条廉价命令重新试"
	case now.Sub(updated) > ReviewAfter:
		return "超过 30 天没复核，可能已过时：用到前先核实，仍成立就原样再 remember 一次刷新"
	}
	return ""
}

// Clean 去掉首尾空白并校验长度
func Clean(content string) (string, error) {
	content = strings.TrimSpace(content)
	if content == "" || utf8.RuneCountInString(content) > MaxRunes {
		return "", errors.New("记忆内容须为 1–500 字")
	}
	return content, nil
}

// Of 组内记忆，人工写的在前，各自按最近更新排；hostnames 用来把资产 ID 换成主机名。需要先复核的 AI 记忆带 review 说明
func Of(ctx context.Context, db *ent.Client, groups []uuid.UUID, hostnames map[uuid.UUID]string) ([]map[string]any, error) {
	// 人工优先要排在 Limit 之前：多组一起读时，别的组较新的 AI 记忆不能把人工记忆挤出去
	humanFirst := func(s *sql.Selector) { s.OrderExpr(sql.Expr(s.C(memory.FieldSource) + " = 'human' DESC")) }
	rows, err := db.Memory.Query().Where(memory.GroupIDIn(groups...)).
		Order(humanFirst, ent.Desc(memory.FieldUpdatedAt)).Limit(Max).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(rows))
	now := time.Now()
	for _, m := range rows {
		item := map[string]any{"id": m.ID, "content": m.Content, "source": m.Source, "updated": m.UpdatedAt.Format("2006-01-02")}
		if note := Review(m.Source, m.Content, m.UpdatedAt, now); note != "" {
			item["review"] = note
		}
		if m.AssetID != nil {
			item["host"] = hostnames[*m.AssetID]
		}
		out = append(out, item)
	}
	return out, nil
}
