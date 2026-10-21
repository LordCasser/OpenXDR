package schedule

import (
	"hash/fnv"
	"time"

	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
)

// Spread 同一任务按组展开时的错峰窗口：每个组在计划时间后 [0, Spread) 内的固定时刻开跑。
// 进程启动时由 SCHEDULE_SPREAD_MINUTES 设置；调度器与任务页的「下次运行」共用，保证两边一致。
var Spread = 15 * time.Minute

// Period 计划时间 plan 到下一次计划时间的间隔，即这一轮的周期；cron 再也不会触发时为 0
func Period(s cron.Schedule, plan time.Time) time.Duration {
	next := s.Next(plan)
	if next.IsZero() {
		return 0
	}
	return next.Sub(plan)
}

// Offset 某组在计划时间 plan 上的开跑偏移：hash(任务, 组) 落在 [0, 窗口) 秒内，
// 窗口取 Spread 与这一轮周期四分之一中较小者——周期短的任务偏移不会吃掉大半个周期，
// 更不会越过下一次计划时间。同一任务同一组、周期不变时每轮偏移相同，便于预期。
func Offset(taskID string, group uuid.UUID, s cron.Schedule, plan time.Time) time.Duration {
	window := min(Spread, Period(s, plan)/4)
	if window < time.Second {
		return 0
	}
	seconds := uint64(window / time.Second)
	h := fnv.New64a()
	_, _ = h.Write([]byte(taskID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(group[:])
	return time.Duration(h.Sum64()%seconds) * time.Second
}

// NextRun 某组 now 之后的下一次开跑时刻（计划时间加偏移），不看上次运行；cron 不再触发时为零值。
// 偏移小于 Spread，所以 now-Spread 之前的计划时间不可能还没开跑，从那里往后找即可。
func NextRun(s cron.Schedule, taskID string, group uuid.UUID, now time.Time) time.Time {
	for plan := s.Next(now.Add(-max(Spread, 0))); !plan.IsZero(); plan = s.Next(plan) {
		if fire := plan.Add(Offset(taskID, group, s, plan)); fire.After(now) {
			return fire
		}
	}
	return time.Time{}
}
