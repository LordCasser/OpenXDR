//go:build integration

package memories

import (
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
)

// 只返回指定组的记忆；人工写的整体在前，各自按最近更新倒序；挂主机的换成主机名
func TestOfOrderAndScope(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	other := db.Group.Create().SetName("other").SaveX(ctx)
	host := db.Asset.Create().SetHostname("pve1").SetGroupID(g.ID).SaveX(ctx)
	unknown := db.Asset.Create().SetHostname("ghost").SetGroupID(g.ID).SaveX(ctx)
	base := time.Now().Add(-time.Hour)

	add := func(group uuid.UUID, content, source string, offset time.Duration, asset *uuid.UUID) {
		c := db.Memory.Create().SetGroupID(group).SetContent(content).SetSource(source).SetAuthor("x").SetUpdatedAt(base.Add(offset))
		if asset != nil {
			c.SetAssetID(*asset)
		}
		c.ExecX(ctx)
	}
	// AI 记忆更新得更晚，也不能排到人工记忆前面
	add(g.ID, "ai-新", "ai", 50*time.Minute, &host.ID)
	add(g.ID, "ai-旧", "ai", 10*time.Minute, nil)
	add(g.ID, "human-旧", "human", time.Minute, nil)
	add(g.ID, "human-新", "human", 5*time.Minute, &unknown.ID)
	add(other.ID, "别组的记忆", "human", 55*time.Minute, nil)

	items, err := Of(ctx, db, []uuid.UUID{g.ID}, map[uuid.UUID]string{host.ID: "pve1"})
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	byContent := map[string]map[string]any{}
	for _, m := range items {
		order = append(order, m["content"].(string))
		byContent[m["content"].(string)] = m
	}
	if want := []string{"human-新", "human-旧", "ai-新", "ai-旧"}; !slices.Equal(order, want) {
		t.Fatalf("记忆顺序 %v, want %v", order, want)
	}
	if h := byContent["ai-新"]["host"]; h != "pve1" {
		t.Errorf("挂主机的记忆应带主机名: %v", h)
	}
	// 主机名表里没有的资产给空串，而不是泄露资产 ID
	if h, ok := byContent["human-新"]["host"]; !ok || h != "" {
		t.Errorf("未知主机应为空串: %v %v", h, ok)
	}
	if _, ok := byContent["ai-旧"]["host"]; ok {
		t.Error("整组记忆不应带 host 字段")
	}
	if m := byContent["human-旧"]; m["source"] != "human" || m["updated"] != base.Add(time.Minute).Format("2006-01-02") {
		t.Errorf("字段不对: %+v", m)
	}

	// 多组一起读：两组的都在
	if both, err := Of(ctx, db, []uuid.UUID{g.ID, other.ID}, nil); err != nil || len(both) != 5 {
		t.Fatalf("多组读取应得 5 条: %d %v", len(both), err)
	}
	// 没有组就什么都不返回，不能退化成读全部
	if none, err := Of(ctx, db, nil, nil); err != nil || len(none) != 0 {
		t.Fatalf("空组列表应返回空: %v %v", none, err)
	}
}

// 单次最多返回 Max 条，截掉的是最久没更新的
func TestOfCapsAtMax(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	base := time.Now().Add(-time.Hour)
	builders := make([]*ent.MemoryCreate, 0, Max+1)
	for i := 0; i <= Max; i++ {
		builders = append(builders, db.Memory.Create().SetGroupID(g.ID).SetContent("m").SetSource("ai").SetAuthor("s").
			SetUpdatedAt(base.Add(time.Duration(i)*time.Second)))
	}
	rows := db.Memory.CreateBulk(builders...).SaveX(ctx)
	oldest := rows[0].ID

	items, err := Of(ctx, db, []uuid.UUID{g.ID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != Max {
		t.Fatalf("应截到 %d 条，实际 %d", Max, len(items))
	}
	for _, m := range items {
		if m["id"] == oldest {
			t.Fatal("最旧的一条应被截掉")
		}
	}
}
