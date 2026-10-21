package schedule

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func withSpread(t *testing.T, d time.Duration) {
	old := Spread
	Spread = d
	t.Cleanup(func() { Spread = old })
}

// 偏移只取决于任务与组：每天同一组同一时刻，落在窗口内，不同组大体错开
func TestOffsetDeterministic(t *testing.T) {
	withSpread(t, 15*time.Minute)
	daily, _ := ParseSchedule("CRON_TZ=Asia/Shanghai 0 10 * * *")
	day := time.Date(2026, 10, 21, 2, 0, 0, 0, time.UTC) // 北京时间 10 点
	seen := map[time.Duration]bool{}
	for range 50 {
		g := uuid.New()
		off := Offset("daily-host-inspection", g, daily, day)
		if off < 0 || off >= 15*time.Minute || off%time.Second != 0 {
			t.Fatalf("偏移越界或不是整秒：%v", off)
		}
		for d := 1; d <= 30; d++ {
			if again := Offset("daily-host-inspection", g, daily, day.AddDate(0, 0, d)); again != off {
				t.Fatalf("同一组第 %d 天偏移变了：%v → %v", d, off, again)
			}
		}
		seen[off] = true
	}
	if len(seen) < 40 {
		t.Errorf("50 个组只有 %d 种偏移，没有错开", len(seen))
	}
	// 不同任务在同一组上也各自错开，免得多个任务同一时刻叠在一个组上
	g := uuid.New()
	if a := Offset("a", g, daily, day); a == Offset("b", g, daily, day) && a == Offset("c", g, daily, day) {
		t.Error("不同任务同一组应各自错峰")
	}
}

// 周期短的任务窗口收到周期的四分之一，永远不会越过下一次计划时间；Spread=0 关闭错峰
func TestOffsetBounds(t *testing.T) {
	withSpread(t, 15*time.Minute)
	plan := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	cases := map[string]time.Duration{
		"*/5 * * * *": 75 * time.Second,
		"* * * * *":   15 * time.Second,
		"0 * * * *":   15 * time.Minute,
		"0 10 * * *":  15 * time.Minute,
	}
	for expr, limit := range cases {
		s, _ := ParseSchedule(expr)
		for range 200 {
			if off := Offset("t", uuid.New(), s, plan); off >= limit {
				t.Fatalf("%s 偏移 %v 超过上限 %v", expr, off, limit)
			}
		}
	}
	// 不规则周期按这一轮到下一轮的间隔算：:00 到 :05 只有 5 分钟
	s, _ := ParseSchedule("0,5 * * * *")
	for range 200 {
		if off := Offset("t", uuid.New(), s, plan); off >= 75*time.Second {
			t.Fatalf("短间隔那一轮偏移 %v 超过 75 秒", off)
		}
	}
	withSpread(t, 0)
	if off := Offset("t", uuid.New(), s, plan); off != 0 {
		t.Errorf("Spread=0 不应偏移：%v", off)
	}
	withSpread(t, -time.Minute)
	if off := Offset("t", uuid.New(), s, plan); off != 0 {
		t.Errorf("负的 Spread 不应偏移：%v", off)
	}
}

// 下次运行 = 计划时间加偏移；偏移时刻还没到时仍是本轮，过了才是下一轮
func TestNextRun(t *testing.T) {
	withSpread(t, 15*time.Minute)
	s, _ := ParseSchedule("CRON_TZ=UTC 0 10 * * *")
	var g uuid.UUID
	for {
		g = uuid.New()
		if Offset("t", g, s, time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)) > time.Minute {
			break
		}
	}
	plan := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	off := Offset("t", g, s, plan)
	if got := NextRun(s, "t", g, plan.Add(-time.Hour)); !got.Equal(plan.Add(off)) {
		t.Errorf("计划前：%v，应 %v", got, plan.Add(off))
	}
	if got := NextRun(s, "t", g, plan.Add(30*time.Second)); !got.Equal(plan.Add(off)) {
		t.Errorf("计划后、偏移前仍是本轮：%v", got)
	}
	if got := NextRun(s, "t", g, plan.Add(off)); !got.Equal(plan.AddDate(0, 0, 1).Add(off)) {
		t.Errorf("到点后应是明天：%v", got)
	}
	never, _ := ParseSchedule("0 0 30 2 *")
	if got := NextRun(never, "t", g, plan); !got.IsZero() {
		t.Errorf("不会触发的 cron 应为零值：%v", got)
	}
}
