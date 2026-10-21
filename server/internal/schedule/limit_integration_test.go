//go:build integration

package schedule

import (
	"context"
	"sync"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/taskrun"
	"openxdr/server/internal/testdb"
)

// gateRunner 每个会话等测试放行一个才结束，像真 Runner 一样落会话终态；记下同时在跑的峰值
type gateRunner struct {
	db      *ent.Client
	started chan Job
	release chan struct{}

	mu            sync.Mutex
	running, peak int
}

func newGateRunner(db *ent.Client) *gateRunner {
	return &gateRunner{db: db, started: make(chan Job, 16), release: make(chan struct{})}
}

func (r *gateRunner) RunTask(ctx context.Context, job Job) error {
	r.mu.Lock()
	r.running++
	r.peak = max(r.peak, r.running)
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.running--
		r.mu.Unlock()
	}()
	r.started <- job
	select {
	case <-r.release:
		return r.db.AgentSession.UpdateOneID(job.Session.ID).SetStatus("succeeded").SetFinishedAt(time.Now()).Exec(context.Background())
	case <-ctx.Done():
		return ctx.Err()
	}
}

// drain 取出已开跑的会话
func (r *gateRunner) drain() []Job {
	var jobs []Job
	for {
		select {
		case j := <-r.started:
			jobs = append(jobs, j)
		default:
			return jobs
		}
	}
}

// settle 等本节点在跑的降到 n：放行后调度器的收尾在后台 goroutine 里
func settle(t *testing.T, s *Scheduler, n int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for s.active.Load() != n {
		if time.Now().After(deadline) {
			t.Fatalf("本节点在跑的应降到 %d，仍为 %d", n, s.active.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func dailyTask(ctx context.Context, db *ent.Client, id string) *ent.Task {
	return db.Task.Create().SetID(id).SetName(id).SetSchedule("CRON_TZ=UTC 0 2 * * *").SetPrompt("检查").
		SetCreatedAt(time.Now().Add(-48 * time.Hour)).SaveX(ctx)
}

func groupWithHost(ctx context.Context, db *ent.Client, name string) *ent.Group {
	g := db.Group.Create().SetName(name).SaveX(ctx)
	db.Asset.Create().SetHostname(name).SetGroupID(g.ID).SaveX(ctx)
	return g
}

// 并发上限：超出的组排队、不建运行记录，前面的结束后下一次检查拉起；人发起的对话会话不占额度；
// 换一个调度器实例（接手的 leader）以库里运行中的会话为准，不会再超发
func TestSchedulerConcurrencyLimitQueues(t *testing.T) {
	ctx, db := testdb.New(t)
	withSpread(t, 0)
	a, b, c := groupWithHost(ctx, db, "a"), groupWithHost(ctx, db, "b"), groupWithHost(ctx, db, "c")
	task := dailyTask(ctx, db, "inspect")
	db.AgentSession.Create().SetKind("chat").SetGroupID(a.ID).SetInitiator("alice").SetModel("m").SaveX(ctx)

	runner := newGateRunner(db)
	s := &Scheduler{DB: db, Runner: runner, DefaultModel: func() string { return "m" }, Timeout: time.Minute, MaxRunning: 2}
	tasks := []*ent.Task{task}
	now := time.Now()
	s.fire(ctx, tasks, now)
	s.fire(ctx, tasks, now)
	if n := db.TaskRun.Query().CountX(ctx); n != 2 {
		t.Fatalf("上限 2 只应建两条运行记录，得到 %d", n)
	}
	if len(s.queued) != 1 {
		t.Fatalf("第三个组应在排队：%v", s.queued)
	}

	// 接手的 leader：内存是空的，但库里有两个在跑
	next := &Scheduler{DB: db, Runner: runner, DefaultModel: func() string { return "m" }, Timeout: time.Minute, MaxRunning: 2}
	next.fire(ctx, tasks, now)
	if n := db.TaskRun.Query().CountX(ctx); n != 2 {
		t.Fatalf("接手的调度器应以库为准不超发，得到 %d 条运行", n)
	}

	runner.release <- struct{}{}
	settle(t, s, 1)
	s.fire(ctx, tasks, now.Add(time.Minute))
	runner.release <- struct{}{}
	runner.release <- struct{}{}
	s.wg.Wait()
	groups := map[string]bool{}
	for _, j := range runner.drain() {
		groups[j.Session.GroupID.String()] = true
	}
	if len(groups) != 3 || !groups[a.ID.String()] || !groups[b.ID.String()] || !groups[c.ID.String()] {
		t.Fatalf("三个组都应跑到：%v", groups)
	}
	if runner.peak > 2 {
		t.Fatalf("同时在跑的会话超过上限：%d", runner.peak)
	}
	if n := db.TaskRun.Query().Where(taskrun.StatusEQ("succeeded")).CountX(ctx); n != 3 {
		t.Fatalf("三轮都应成功，得到 %d", n)
	}
	if len(s.queued) != 0 {
		t.Fatalf("拉起后排队项应清掉：%v", s.queued)
	}
}

// 排队满一个周期仍没轮到就跳过、留 skipped 记录；下一轮从跳过时刻起算，不会接着补跑。
// 额度被别的节点上未收尾的任务会话占着，也算数
func TestSchedulerSkipsAfterQueueingAPeriod(t *testing.T) {
	ctx, db := testdb.New(t)
	withSpread(t, 0)
	g := groupWithHost(ctx, db, "a")
	other := db.Group.Create().SetName("other").SaveX(ctx) // 没有主机，任务不在这组跑
	task := dailyTask(ctx, db, "inspect")
	foreign := db.AgentSession.Create().SetKind("task").SetGroupID(other.ID).SetInitiator(Initiator).SetModel("m").SaveX(ctx)

	runner := newGateRunner(db)
	s := &Scheduler{DB: db, Runner: runner, DefaultModel: func() string { return "m" }, Timeout: time.Minute, MaxRunning: 1}
	tasks := []*ent.Task{task}
	now := time.Now()
	s.fire(ctx, tasks, now)
	s.fire(ctx, tasks, now.Add(23*time.Hour))
	if n := db.TaskRun.Query().CountX(ctx); n != 0 {
		t.Fatalf("额度被占着不应开跑或跳过，得到 %d 条运行", n)
	}
	s.fire(ctx, tasks, now.Add(24*time.Hour))
	run := db.TaskRun.Query().OnlyX(ctx)
	if run.Status != StatusSkipped || run.Error == nil || *run.Error != SkipReason || run.GroupID != g.ID || run.ScheduledAt == nil {
		t.Fatalf("排队满一个周期应记跳过：%+v", run)
	}

	// 别的节点那个会话收尾后额度空出来；刚跳过的这一轮不补跑，下一轮到点才跑
	db.AgentSession.UpdateOneID(foreign.ID).SetStatus("failed").ExecX(ctx)
	s.fire(ctx, tasks, now.Add(24*time.Hour+time.Minute))
	if n := db.TaskRun.Query().CountX(ctx); n != 1 {
		t.Fatalf("跳过的一轮不应接着补跑，得到 %d 条运行", n)
	}
	s.fire(ctx, tasks, now.Add(49*time.Hour))
	if n := db.TaskRun.Query().CountX(ctx); n != 2 {
		t.Fatalf("下一轮应照常运行，得到 %d 条运行", n)
	}
	runner.release <- struct{}{}
	s.wg.Wait()
}

// 立即运行不错峰、受上限但优先：额度只剩一个时先跑人点的，定时到期的排在后面
func TestSchedulerManualRunFirst(t *testing.T) {
	ctx, db := testdb.New(t)
	withSpread(t, 15*time.Minute)
	g := groupWithHost(ctx, db, "a")
	dailyTask(ctx, db, "scheduled")
	db.Task.Create().SetID("manual").SetName("manual").SetSchedule("CRON_TZ=UTC 0 2 * * *").SetPrompt("检查").
		SetCreatedAt(time.Now().Add(-time.Minute)).SetRunRequestedAt(time.Now()).SaveX(ctx)
	manual := db.Task.GetX(ctx, "manual")

	runner := newGateRunner(db)
	s := &Scheduler{DB: db, Runner: runner, DefaultModel: func() string { return "m" }, Timeout: time.Minute, MaxRunning: 1}
	tasks := db.Task.Query().AllX(ctx)
	now := time.Now().Add(time.Second)
	s.fire(ctx, tasks, now)
	select {
	case job := <-runner.started:
		if job.Session.Title == nil || *job.Session.Title != "manual" {
			t.Fatalf("应先跑立即运行的任务：%+v", job.Session)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("没有任务开跑")
	}
	if n := db.TaskRun.Query().CountX(ctx); n != 1 {
		t.Fatalf("上限 1 只应开跑一个，得到 %d", n)
	}
	run := db.TaskRun.Query().Where(taskrun.TaskIDEQ("manual")).OnlyX(ctx)
	if !run.ScheduledAt.Equal(*manual.RunRequestedAt) {
		t.Errorf("立即运行不错峰，计划时间应是请求时刻：%v", run.ScheduledAt)
	}
	runner.release <- struct{}{}
	settle(t, s, 0)
	s.fire(ctx, tasks, now)
	runner.release <- struct{}{}
	s.wg.Wait()
	if n := db.TaskRun.Query().Where(taskrun.TaskIDEQ("scheduled"), taskrun.GroupIDEQ(g.ID)).CountX(ctx); n != 1 {
		t.Fatalf("定时到期的一轮应随后拉起，得到 %d", n)
	}
}
