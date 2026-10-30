//go:build integration

// P0 反例集成测试：把 COLD_ARCHIVE_EVOLUTION.SCRATCH.md 问题登记册 #2 的两条数据丢失路径
// （5.2 节 T01/T02）从「推导」变成「确定性实测」。本文件断言的是**当前实现（有缺陷）的行为**
// 且必须全部通过；每个反例都带 `// P3 翻转:` 注释说明修复后应断言什么，P3 实施时改断言即可。
//
// 两条反例共用同一个事实基础：Swap 的删除门禁是「冷块条数 == 计划移出条数」的计数校验，
// 且发生在重写事务之外（先 Plan/coldCount，后 RewriteDay 加锁重建分区）。
package eventarchive

import (
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// T01（串行抵消反例，断言现状）：当日未 pin 的 A、B → shadow + verify → 给 A 建 alert 引用（待删集 −1）
// → 再插入同日未 pin 的 C（+1）。计数门禁仍然相等（冷 2 == 待移出 2），Swap 照常执行：
// 有冷副本的 B 被移出，而 C 从未进过冷块也被一并删除——静默丢失，无任何副本、无任何报错。
//
// P3 翻转：swap 必须拒绝，或 C 保留在热表（实际删除集 D 的每一行都必须有已验证冷副本）。
func TestP0T01SerialCancellationDeletesRowWithoutColdCopy(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 1)
	a := p0Event(t, ctx, client, day.Add(10*time.Minute), 4001, "agent", `{"mark":"A","conn":{"dst":"10.0.0.1:443"}}`)
	b := p0Event(t, ctx, client, day.Add(20*time.Minute), 4001, "agent", `{"mark":"B","conn":{"dst":"10.0.0.2:443"}}`)

	runID := p0VerifiedRun(t, ctx, db, day, day)

	// 对拍通过之后再动 events：钉住 A（待删集 −1），插入同日同口径的 C（+1）
	p0Pin(t, ctx, client, day.Add(10*time.Minute), a)
	c := p0Event(t, ctx, client, day.Add(30*time.Minute), 4001, "agent", `{"mark":"C","conn":{"dst":"10.0.0.7:443"}}`)

	p, err := Plan(ctx, db, runID, day)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if p.Archived != 2 || p.KeepPinned != 1 {
		t.Fatalf("现状：计划应是 待移出=2（B、C）、钉住=1（A），实际 %+v", p)
	}
	cold := p0ColdDayCount(t, ctx, db, runID, day)
	if cold != 2 || cold != p.Archived {
		t.Fatalf("现状：计数门禁必须仍然相等（冷块 %d 条 == 计划移出 %d 条），否则反例不成立", cold, p.Archived)
	}

	if _, err := Swap(ctx, db, runID, day); err != nil {
		t.Fatalf("现状：计数相等时 Swap 必须成功执行，实际 %v", err)
	}

	// A 被钉住，留在热表
	if !p0HotExists(t, ctx, db, a) {
		t.Fatal("被钉住的 A 应留在热表")
	}
	// B 被移出热表，冷层有副本：这是预期中的正常行为
	if p0HotExists(t, ctx, db, b) {
		t.Fatal("B 应已移出热表")
	}
	if _, found, err := Locate(ctx, db, b); err != nil || !found {
		t.Fatalf("B 的冷副本必须可定位：found=%v err=%v", found, err)
	}
	// C 同样被移出热表，但冷层**确定没有**它：C 无任何副本——静默丢失
	if p0HotExists(t, ctx, db, c) {
		t.Fatal("C 应已被 Swap 删除（这正是缺陷）")
	}
	_, found, err := Locate(ctx, db, c)
	if err != nil {
		t.Fatalf("定位 C 不该报错（报错就无法断言确定不存在）: %v", err)
	}
	if found {
		t.Fatal("C 从未进冷块，冷层不应命中")
	}
	// 走到这里：热表没有 C、冷层确定没有 C —— C 在世界上已不存在
	if got := p0PartitionRows(t, ctx, db, day); got != 1 {
		t.Fatalf("切换后日分区应只剩 A 一行，实际 %d 行", got)
	}
}

// T02（检查后、加锁前的 TOCTOU 反例，确定性同步、无 sleep）：goroutine 里跑 Swap，
// swapTestHook 在「预检已完成、重写事务未开始」的确切位置（stage == "prechecks_done"）回调；
// 测试主协程收到信号后，经一条**独立连接**向同日写入未 pin 的口径内事件 C，再放行 Swap。
// 现状：分区照样重建，A/B/C 全部移出，其中 C 没有任何冷副本；Swap 只能在重写提交**之后**
// 才发现计数与计划不符并报错——检测存在，但删除已经提交，无法挽回。
//
// P3 翻转：同窗口内插入的行必须留热（实际删除依据不能有 TOCTOU 空洞，见 1.2 节 D/K 定义）。
func TestP0T02InsertBetweenPrecheckAndLockLosesRow(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 1)
	a := p0Event(t, ctx, client, day.Add(10*time.Minute), 4001, "agent", `{"mark":"A","conn":{"dst":"10.0.0.1:443"}}`)
	b := p0Event(t, ctx, client, day.Add(20*time.Minute), 4001, "agent", `{"mark":"B","conn":{"dst":"10.0.0.2:443"}}`)

	runID := p0VerifiedRun(t, ctx, db, day, day)

	// 独立连接：与 Swap 走的连接池完全分开，模拟另一路并发写入方（接入进程）
	inserter, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inserter.Close() })

	// 双通道屏障：钩子在 Swap 协程里触发（预检已过）→ 通知主协程 → 主协程写入 C 并放行。
	// Swap 协程阻塞在钩子里时，RewriteDay 的事务还没开，日分区上没有任何锁，
	// 独立连接的 INSERT 不需要等待，时序完全确定。
	prechecksDone := make(chan struct{})
	release := make(chan struct{})
	swapTestHook = func(stage string) {
		if stage != "prechecks_done" {
			t.Errorf("钩子只允许 prechecks_done 一个阶段值，实际 %q", stage)
		}
		close(prechecksDone)
		<-release
	}
	t.Cleanup(func() { swapTestHook = nil })

	type swapOutcome struct {
		plan SwapPlan
		err  error
	}
	done := make(chan swapOutcome, 1)
	go func() {
		plan, err := Swap(ctx, db, runID, day)
		done <- swapOutcome{plan: plan, err: err}
	}()

	select {
	case <-prechecksDone:
	case <-time.After(time.Minute):
		t.Fatal("钩子没有在预检完成后触发：Swap 在前置检查阶段就失败了，反例前提不成立")
	}

	c := uuid.New()
	if _, err := inserter.ExecContext(ctx, `INSERT INTO events (id, ts, class_uid, source, raw)
 VALUES ($1, $2, 4001, 'agent', $3::jsonb)`,
		c, day.Add(45*time.Minute), `{"mark":"C-race","conn":{"dst":"10.0.0.8:443"}}`); err != nil {
		t.Fatalf("在竞态窗口内写入 C: %v", err)
	}
	close(release)

	var outcome swapOutcome
	select {
	case outcome = <-done:
	case <-time.After(time.Minute):
		t.Fatal("Swap 在放行后没有返回")
	}

	// 现状：分区已经按实际口径重建（整日清空），Swap 只能事后报告与计划不符；
	// 检测是重写提交之后才发生的，不能防止丢失
	if outcome.err == nil || !strings.Contains(outcome.err.Error(), "结果与计划不符") {
		t.Fatalf("现状：窗口内多删一行时 Swap 只能事后报「结果与计划不符」，实际 %v", outcome.err)
	}
	for _, id := range []uuid.UUID{a, b} {
		if p0HotExists(t, ctx, db, id) {
			t.Fatalf("事件 %s 应已随分区重建移出热表", id)
		}
		if _, found, err := Locate(ctx, db, id); err != nil || !found {
			t.Fatalf("事件 %s 的冷副本必须可定位：found=%v err=%v", id, found, err)
		}
	}
	// C：热表没有、冷层确定没有——竞态窗口真实造成了无副本删除
	if p0HotExists(t, ctx, db, c) {
		t.Fatal("C 应已被 Swap 删除（这正是竞态缺陷）")
	}
	_, found, err := Locate(ctx, db, c)
	if err != nil {
		t.Fatalf("定位 C 不该报错: %v", err)
	}
	if found {
		t.Fatal("C 是窗口内新写入的，冷层不应有它的副本")
	}
	if got := p0PartitionRows(t, ctx, db, day); got != 0 {
		t.Fatalf("现状：分区应已重建为空（A/B/C 全部移出），实际 %d 行", got)
	}
}
