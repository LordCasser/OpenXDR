package main

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/temporal"
)

func repositoryBacktest(t *testing.T) *temporalBacktest {
	t.Helper()
	root := filepath.Join("..", "..", "..")
	store := &temporal.Store{}
	if err := store.Reload(filepath.Join(root, "rules"), filepath.Join(root, "temporal-rules")); err != nil {
		t.Fatal(err)
	}
	return newTemporalBacktest(store.Current(), store.Rules(), 2)
}

// 按时间顺序喂入认证失败，核对两种实体维度的命中、分布、样例证据与覆盖缺口。
func TestTemporalBacktestReplay(t *testing.T) {
	b := repositoryBacktest(t)
	group := uuid.NullUUID{UUID: uuid.New(), Valid: true}
	hosts := []uuid.NullUUID{{UUID: uuid.New(), Valid: true}, {UUID: uuid.New(), Valid: true}, {UUID: uuid.New(), Valid: true}}
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	feed := func(host, seconds int, username string, group uuid.NullUUID) uuid.UUID {
		t.Helper()
		doc := map[string]any{"activity_id": float64(1), "status_id": float64(2)}
		c := candidate{id: uuid.New(), ts: start.Add(time.Duration(seconds) * time.Second), group: group, asset: hosts[host], host: []string{"web-1", "web-2", "web-3"}[host], username: username}
		if c.rules = b.candidateOf(3002, "linux", doc, username); len(c.rules) == 0 {
			t.Fatal("认证失败未命中基础规则")
		}
		if err := b.apply(c); err != nil {
			t.Fatal(err)
		}
		return c.id
	}
	// 同账号分布在三台主机：只有账号维度命中
	var spread []uuid.UUID
	for i := range 5 {
		spread = append(spread, feed(i%3, i*60, "Admin", group))
	}
	// 一小时后同一主机五次、换账号：只命中资产维度，账号规则要求至少两台资产
	var burst []uuid.UUID
	for i := range 5 {
		burst = append(burst, feed(0, 3600+i, "deploy", group))
	}
	// 无用户名、无组的失败不参与对应维度
	feed(1, 7200, "", group)
	feed(1, 7201, "admin", uuid.NullUUID{})

	account := b.stats["temporal:linux-account-auth-burst"]
	asset := b.stats["temporal:linux-auth-burst"]
	if account.hits != 1 || account.entities["account:admin"] != 1 || account.entities["account:deploy"] != 0 || account.groupBy != temporal.GroupByAccount {
		t.Fatalf("账号维度回测错误: %+v", account)
	}
	if asset.hits != 1 || asset.entities["web-1"] != 1 || asset.groupBy != temporal.GroupByAsset {
		t.Fatalf("资产维度回测错误: %+v", asset)
	}
	if len(account.samples) != 1 || !slices.Equal(account.samples[0], spread) || !slices.Equal(asset.samples[0], burst) {
		t.Fatalf("样例证据错误: %v %v", account.samples, asset.samples)
	}
	if b.skipped["no_account"] != 1 || b.skipped["unscoped"] != 1 || b.candidates != 12 {
		t.Fatalf("覆盖缺口计数错误: %v %d", b.skipped, b.candidates)
	}
	// 读取顺序倒退必须报错，不能给出错误的命中数
	if err := b.apply(candidate{id: uuid.New(), ts: start, group: group, asset: hosts[0], rules: []string{"9c4e6b2d-8f13-47a5-9e07-3d5a8c1f6b42"}}); err == nil {
		t.Fatal("乱序输入必须拒绝")
	}
}
