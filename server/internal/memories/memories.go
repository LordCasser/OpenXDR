// Package memories 组内长期记忆的读取与校验：对话、巡检与研判共用同一份口径。
package memories

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/memory"
)

// Max 每组记忆上限：满了要先删过时的，逼着记忆保持精炼
const Max = 200

// MaxRunes 一条记忆的长度上限
const MaxRunes = 500

// Clean 去掉首尾空白并校验长度
func Clean(content string) (string, error) {
	content = strings.TrimSpace(content)
	if content == "" || utf8.RuneCountInString(content) > MaxRunes {
		return "", errors.New("记忆内容须为 1–500 字")
	}
	return content, nil
}

// Of 组内记忆，人工写的在前，各自按最近更新排；hostnames 用来把资产 ID 换成主机名
func Of(ctx context.Context, db *ent.Client, groups []uuid.UUID, hostnames map[uuid.UUID]string) ([]map[string]any, error) {
	rows, err := db.Memory.Query().Where(memory.GroupIDIn(groups...)).
		Order(ent.Desc(memory.FieldUpdatedAt)).Limit(Max).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(rows))
	for _, human := range []bool{true, false} {
		for _, m := range rows {
			if (m.Source == "human") != human {
				continue
			}
			item := map[string]any{"id": m.ID, "content": m.Content, "source": m.Source, "updated": m.UpdatedAt.Format("2006-01-02")}
			if m.AssetID != nil {
				item["host"] = hostnames[*m.AssetID]
			}
			out = append(out, item)
		}
	}
	return out, nil
}
