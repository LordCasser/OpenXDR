package schedule

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entasset "openxdr/server/ent/asset"
	entgroup "openxdr/server/ent/group"
	"openxdr/server/ent/report"
	enttask "openxdr/server/ent/task"
	"openxdr/server/ent/taskrun"
	"openxdr/server/internal/commandgate"
)

// StatusInterrupted 运行被停机或失去租约打断：结果不算数，接手的 leader 用新会话重跑
const StatusInterrupted = "interrupted"

// Initiator 定时任务会话的发起人，即审批闸门的系统身份。
const Initiator = commandgate.SystemActor

// Job 一次任务运行：会话已建好（kind=task、initiator=system、绑定组与模型）。
type Job struct {
	Session         *ent.AgentSession
	Prompt          string
	ApprovalTimeout time.Duration
}

// Runner 以系统身份跑完一次任务会话。会话状态由 Runner 落库；
// 输出截断、轮数耗尽等未完整结束的情况必须返回错误，不能算成功。
type Runner interface {
	RunTask(ctx context.Context, job Job) error
}

// Notifier 任务结果外发，nil 表示不外发。
// Notifier 推送一条通知；path 是控制台内的相对链接，由推送端拼前缀。
type Notifier func(ctx context.Context, title, text, path string) error

type Scheduler struct {
	DB     *ent.Client
	Runner Runner
	Dir    string
	// 检查到期与重载 YAML 的周期
	Interval time.Duration
	// 任务未指定模型时使用（控制台可改，每轮取）；为空表示 Pi 未启用，任务照常同步但不运行
	DefaultModel func() string
	Notify       Notifier
	// 单次运行上限，含模型、工具与审批等待
	Timeout time.Duration

	start time.Time
	wg    sync.WaitGroup
	slots chan struct{}
}

// Run 集群单活；遗留会话由执行期限清理器处理，接管时不修改其他节点的活跃运行。
func (s *Scheduler) Run(ctx context.Context) {
	s.start = time.Now()
	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()
	defer s.wg.Wait()
	for {
		if err := s.tick(ctx, time.Now()); err != nil {
			slog.Error("任务调度批次失败", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Scheduler) tick(ctx context.Context, now time.Time) error {
	if err := Sync(ctx, s.DB, LoadDir(s.Dir)); err != nil {
		return err
	}
	tasks, err := s.DB.Task.Query().Where(enttask.Enabled(true), enttask.Removed(false)).All(ctx)
	if err != nil {
		return err
	}
	for _, t := range tasks {
		s.fireDue(ctx, t, now)
	}
	return nil
}

// due 按组从上次运行起算；从未运行的组使用任务的持久创建时间。
// 停机或停用期间错过的多个周期只补跑一次。
func (s *Scheduler) due(ctx context.Context, t *ent.Task, groupID uuid.UUID, now time.Time) (time.Time, error) {
	expr := t.Schedule
	if t.CustomSchedule != nil {
		expr = *t.CustomSchedule
	}
	sched, err := ParseSchedule(expr)
	if err != nil {
		return time.Time{}, err
	}
	base := t.CreatedAt
	last, err := s.DB.TaskRun.Query().Where(taskrun.TaskIDEQ(t.ID), taskrun.GroupIDEQ(groupID)).
		Order(ent.Desc(taskrun.FieldStartedAt)).First(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return time.Time{}, err
	}
	if last != nil {
		base = last.StartedAt
	}
	// 手动请求晚于上次运行就立即跑；计划时间记请求时刻，集群内同一请求只跑一轮
	if r := t.RunRequestedAt; r != nil && r.After(base) && !r.After(now) {
		return *r, nil
	}
	next := sched.Next(base)
	if next.After(now) {
		return time.Time{}, nil
	}
	return next, nil
}

// fire 每个目标组一个会话。空组不跑；上一轮还在跑的组跳过本轮，不叠加。
func (s *Scheduler) fire(ctx context.Context, t *ent.Task) { s.fireDue(ctx, t, time.Now()) }

func (s *Scheduler) fireDue(ctx context.Context, t *ent.Task, now time.Time) {
	if s.slots == nil {
		s.slots = make(chan struct{}, 4)
	}
	q := s.DB.Group.Query()
	if t.TargetGroup != "*" {
		q = q.Where(entgroup.NameEQ(t.TargetGroup))
	}
	groups, err := q.All(ctx)
	if err != nil {
		slog.Error("查询任务目标组失败", "task", t.ID, "err", err)
		return
	}
	if len(groups) == 0 {
		slog.Warn("任务没有可用的目标组", "task", t.ID, "group", t.TargetGroup)
	}
	// 任务自带模型也得在 Pi 启用时才跑：端点与密钥跟着平台配置走
	def := s.DefaultModel()
	if def == "" {
		return
	}
	model := t.Model
	if model == "" {
		model = def
	}
	for _, g := range groups {
		// 上一轮被停机打断的先接着重跑，不等下一个周期
		retry, err := s.interrupted(ctx, t, g.ID, now)
		if err != nil {
			slog.Error("查询被打断的任务运行失败", "task", t.ID, "group", g.ID, "err", err)
			continue
		}
		var scheduled time.Time
		if retry == nil {
			if scheduled, err = s.due(ctx, t, g.ID, now); err != nil {
				slog.Error("任务到期判断失败", "task", t.ID, "group", g.ID, "err", err)
				continue
			}
			if scheduled.IsZero() {
				continue
			}
		}
		n, err := s.DB.Asset.Query().Where(entasset.GroupIDEQ(g.ID)).Count(ctx)
		if err != nil || n == 0 {
			continue
		}
		busy, err := s.DB.TaskRun.Query().
			Where(taskrun.TaskIDEQ(t.ID), taskrun.GroupIDEQ(g.ID), taskrun.StatusEQ("running")).
			Exist(ctx)
		if err != nil || busy {
			if busy {
				slog.Warn("上一轮仍在运行，跳过本轮", "task", t.ID, "group", g.Name)
			}
			continue
		}
		select {
		case s.slots <- struct{}{}:
		case <-ctx.Done():
			return
		}
		run, session := retry, (*ent.AgentSession)(nil)
		if retry != nil {
			slog.Info("重跑被停机打断的任务", "task", t.ID, "group", g.Name, "run", retry.ID)
			session, err = s.rerun(ctx, t, g, retry, model)
		} else {
			run, session, err = s.begin(ctx, t, g, model, scheduled)
		}
		if err != nil {
			<-s.slots
			slog.Error("创建任务运行失败", "task", t.ID, "group", g.Name, "err", err)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.slots }()
			s.execute(ctx, t, g, run, session)
		}()
	}
}

// interruptedWithin 多久以内被打断的运行才重跑：再早的那一轮已经过时，等下一个周期
const interruptedWithin = 12 * time.Hour

// interrupted 这个组上一轮是否被停机打断、还值得重跑。只看最近一轮：之后已经跑过就不补
func (s *Scheduler) interrupted(ctx context.Context, t *ent.Task, groupID uuid.UUID, now time.Time) (*ent.TaskRun, error) {
	last, err := s.DB.TaskRun.Query().Where(taskrun.TaskIDEQ(t.ID), taskrun.GroupIDEQ(groupID)).
		Order(ent.Desc(taskrun.FieldStartedAt)).First(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if last.Status != StatusInterrupted || last.StartedAt.Before(now.Add(-interruptedWithin)) {
		return nil, nil
	}
	return last, nil
}

func (s *Scheduler) begin(ctx context.Context, t *ent.Task, g *ent.Group, model string, scheduled time.Time) (*ent.TaskRun, *ent.AgentSession, error) {
	tx, err := s.DB.Tx(ctx)
	if err != nil {
		return nil, nil, err
	}
	session, err := s.newSession(ctx, tx, t, g, model)
	if err != nil {
		_ = tx.Rollback()
		return nil, nil, err
	}
	run, err := tx.TaskRun.Create().
		SetTaskID(t.ID).SetGroupID(g.ID).SetSessionID(session.ID).SetScheduledAt(scheduled).
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		return nil, nil, err
	}
	return run, session, tx.Commit()
}

// rerun 同一轮运行换一个新会话重跑：一个计划时间只占一行运行记录（唯一索引），
// 失败那次的会话与错误仍留在 agent_sessions 里可查。
func (s *Scheduler) rerun(ctx context.Context, t *ent.Task, g *ent.Group, run *ent.TaskRun, model string) (*ent.AgentSession, error) {
	tx, err := s.DB.Tx(ctx)
	if err != nil {
		return nil, err
	}
	session, err := s.newSession(ctx, tx, t, g, model)
	if err == nil {
		err = tx.TaskRun.UpdateOneID(run.ID).SetSessionID(session.ID).SetStatus("running").
			ClearFinishedAt().ClearError().Exec(ctx)
	}
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return session, tx.Commit()
}

func (s *Scheduler) newSession(ctx context.Context, tx *ent.Tx, t *ent.Task, g *ent.Group, model string) (*ent.AgentSession, error) {
	return tx.AgentSession.Create().
		SetKind("task").SetGroupID(g.ID).SetInitiator(Initiator).SetModel(model).
		SetTitle(t.Name).SetRunExpiresAt(time.Now().Add(s.runTimeout() + time.Minute)).
		Save(ctx)
}

func (s *Scheduler) execute(ctx context.Context, t *ent.Task, g *ent.Group, run *ent.TaskRun, session *ent.AgentSession) {
	err := s.attempt(ctx, t, g, run, session)
	// 停机或失去租约打断的：已记为 interrupted，由接手的 leader 重跑，不算失败也不通知
	if err != nil && ctx.Err() != nil {
		return
	}
	// 模型偶尔乱写、漏交报告，换个新会话重跑一次通常就好；超时与失去租约不重跑
	if err != nil && ctx.Err() == nil && !errors.Is(err, context.DeadlineExceeded) {
		slog.Warn("任务失败，新开会话重试一次", "task", t.ID, "group", g.Name, "err", err)
		if next, rerr := s.rerun(ctx, t, g, run, session.Model); rerr != nil {
			slog.Error("创建重试会话失败", "task", t.ID, "group", g.Name, "err", rerr)
		} else {
			session = next
			err = s.attempt(ctx, t, g, run, session)
		}
	}

	done, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err == nil {
		s.pushReports(done, g, session)
		return
	}
	// 巡检失败不能悄无声息：没人看控制台时，Webhook 是唯一的信号
	if s.Notify != nil {
		text := fmt.Sprintf("组「%s」的任务重试后仍失败：%v", g.Name, err)
		if nerr := s.Notify(done, "任务失败："+t.Name, text, "/?session="+session.ID.String()); nerr != nil {
			slog.Error("任务失败通知发送失败", "run", run.ID, "err", nerr)
		}
	}
}

// attempt 跑一次会话并落终态。
func (s *Scheduler) attempt(ctx context.Context, t *ent.Task, g *ent.Group, run *ent.TaskRun, session *ent.AgentSession) error {
	runCtx, cancel := context.WithTimeout(ctx, s.runTimeout())
	defer cancel()
	slog.Info("任务开始", "task", t.ID, "group", g.Name, "session", session.ID)
	err := s.Runner.RunTask(runCtx, Job{
		Session:         session,
		Prompt:          t.Prompt,
		ApprovalTimeout: time.Duration(t.ApprovalTimeoutSeconds) * time.Second,
	})

	// 节点失去租约时 ctx 已取消，终态仍要落库
	done, cancelDone := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancelDone()
	update := s.DB.TaskRun.UpdateOneID(run.ID).Where(taskrun.StatusEQ("running")).SetFinishedAt(time.Now()).SetStatus("succeeded")
	if err != nil {
		status := "failed"
		if ctx.Err() != nil {
			status = StatusInterrupted
		}
		update.SetStatus(status).SetError(err.Error())
	}
	if uerr := update.Exec(done); uerr != nil {
		slog.Error("保存任务运行终态失败", "run", run.ID, "err", uerr)
	}
	if err != nil {
		slog.Error("任务失败", "task", t.ID, "group", g.Name, "err", err)
		return err
	}
	slog.Info("任务完成", "task", t.ID, "group", g.Name)
	return nil
}

// pushReports 把会话提交的报告推出去：标题、摘要与控制台里的 HTML 链接。
// 推送失败只记日志，报告本身已在库里。
func (s *Scheduler) pushReports(ctx context.Context, g *ent.Group, session *ent.AgentSession) {
	if s.Notify == nil {
		return
	}
	reports, err := s.DB.Report.Query().Where(report.SessionIDEQ(session.ID)).Order(ent.Asc(report.FieldCreatedAt)).All(ctx)
	if err != nil {
		slog.Error("查询任务报告失败", "session", session.ID, "err", err)
		return
	}
	for _, r := range reports {
		text := fmt.Sprintf("组「%s」\n%s", g.Name, excerpt(r.Markdown, 300))
		if err := s.Notify(ctx, r.Title, text, "/api/agent-reports/"+r.ID.String()+"/html"); err != nil {
			slog.Error("报告推送失败", "report", r.ID, "err", err)
		}
	}
}

// excerpt 按字符截断，IM 消息里放全文没人看
func excerpt(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n]) + "…"
}

func (s *Scheduler) runTimeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return 30 * time.Minute
}
