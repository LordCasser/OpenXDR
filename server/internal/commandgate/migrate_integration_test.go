//go:build integration

package commandgate

import (
	"slices"
	"strings"
	"testing"

	"openxdr/server/ent/commandpolicy"
	"openxdr/server/internal/testdb"
)

// 有旧免审批名单的组换成默认高风险名单；人工名单不动；再跑一次什么都不变，
// 管理员清空的黑名单也不会被补回来。
func TestMigrateAllowToDeny(t *testing.T) {
	ctx, db := testdb.New(t)
	legacy := db.Group.Create().SetName("legacy").SaveX(ctx)
	db.Group.Create().SetName("cleared").SaveX(ctx)
	for _, p := range []string{"uptime", "df -hT"} {
		db.CommandPolicy.Create().SetGroupID(legacy.ID).SetOrigin(commandpolicy.OriginAi).SetMode(commandpolicy.ModeAllow).SetPattern(p).SaveX(ctx)
	}
	db.CommandPolicy.Create().SetGroupID(legacy.ID).SetOrigin(commandpolicy.OriginHuman).SetMode(commandpolicy.ModeDeny).SetPattern("reboot").SaveX(ctx)

	count := func(origin commandpolicy.Origin, mode commandpolicy.Mode) map[string]int {
		out := map[string]int{}
		for _, g := range db.Group.Query().AllX(ctx) {
			out[g.Name] = db.CommandPolicy.Query().Where(commandpolicy.GroupIDEQ(g.ID), commandpolicy.OriginEQ(origin), commandpolicy.ModeEQ(mode)).CountX(ctx)
		}
		return out
	}
	for range 2 {
		if err := MigrateAllowToDeny(ctx, db); err != nil {
			t.Fatal(err)
		}
		if n := count(commandpolicy.OriginAi, commandpolicy.ModeAllow); n["legacy"] != 0 {
			t.Fatalf("allow 行应删光：%v", n)
		}
		deny := count(commandpolicy.OriginAi, commandpolicy.ModeDeny)
		if deny["legacy"] != len(DefaultAIDeny) || deny["cleared"] != 0 {
			t.Fatalf("只应给删到 allow 行的组补一份默认名单：%v", deny)
		}
		if n := count(commandpolicy.OriginHuman, commandpolicy.ModeDeny); n["legacy"] != 1 {
			t.Fatalf("人工名单不应变动：%v", n)
		}
	}
	// 管理员把黑名单全删了，重启也不补回来
	db.CommandPolicy.Delete().Where(commandpolicy.GroupIDEQ(legacy.ID), commandpolicy.OriginEQ(commandpolicy.OriginAi)).ExecX(ctx)
	if err := MigrateAllowToDeny(ctx, db); err != nil {
		t.Fatal(err)
	}
	if n := count(commandpolicy.OriginAi, commandpolicy.ModeDeny); n["legacy"] != 0 {
		t.Fatalf("清空的名单被补回：%v", n)
	}
}

// 仍是旧写法的默认条目换成新写法；管理员改过的和人工条目不动；再跑一次不变
func TestUpgradeDefaults(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	i := slices.IndexFunc(DefaultAIDeny, func(p string) bool { return strings.HasPrefix(p, cmdPos) })
	pattern := DefaultAIDeny[i]
	old := strings.Replace(pattern, cmdPos, legacyCmdPos, 1)
	db.CommandPolicy.Create().SetGroupID(g.ID).SetOrigin(commandpolicy.OriginAi).SetMode(commandpolicy.ModeDeny).SetPattern(old).SaveX(ctx)
	db.CommandPolicy.Create().SetGroupID(g.ID).SetOrigin(commandpolicy.OriginAi).SetMode(commandpolicy.ModeDeny).SetPattern(old + "x").SaveX(ctx)
	for range 2 {
		if err := UpgradeDefaults(ctx, db); err != nil {
			t.Fatal(err)
		}
		// 在 Go 里排序再比：库里的排序随 collation 变（CI 的 en_US 与本地的 C 对标点排法不同）
		got := db.CommandPolicy.Query().Select(commandpolicy.FieldPattern).StringsX(ctx)
		want := []string{pattern, old + "x"}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Fatalf("升级结果不对：%q", got)
		}
	}
}
