package schedule

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"openxdr/server/ent"
	entasset "openxdr/server/ent/asset"
	entgroup "openxdr/server/ent/group"
	"openxdr/server/ent/report"
	enttask "openxdr/server/ent/task"
	"openxdr/server/ent/taskrun"
	"openxdr/server/internal/commandgate"
)

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
type Notifier func(ctx context.Context, title, text string) error

type Scheduler struct {
	DB     *ent.Client
	Runner Runner
	Dir    string
	// 检查到期与重载 YAML 的周期
	Interval time.Duration
	// 任务未指定模型时使用
	DefaultModel string
	Notify       Notifier
	// 控制台链接前缀，拼进失败通知
	LinkBase string
	// 单次运行上限，含模型、工具与审批等待
	Timeout time.Duration

	start time.Time
	wg    sync.WaitGroup
}

// Run 集群单活。接管时先把遗留的 running 记为失败：上一个调度节点已经没了，结果未知，不重放。
func (s *Scheduler) Run(ctx context.Context) {
	s.start = time.Now()
	if err := s.DB.TaskRun.Update().Where(taskrun.StatusEQ("running")).
		SetStatus("failed").SetError("调度节点中断，结果未知").SetFinishedAt(s.start).
		Exec(ctx); err != nil {
		slog.Error("清理遗留任务运行失败", "err", err)
	}
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
		due, err := s.due(ctx, t, now)
		if err != nil {
			slog.Error("任务到期判断失败", "task", t.ID, "err", err)
			continue
		}
		if due {
			s.fire(ctx, t)
		}
	}
	return nil
}

// due 从上一次运行（从没跑过就从本节点接管时刻）起算下一个触发点。
// 停机或停用期间错过的多个周期只补跑一次。
func (s *Scheduler) due(ctx context.Context, t *ent.Task, now time.Time) (bool, error) {
	expr := t.Schedule
	if t.CustomSchedule != nil {
		expr = *t.CustomSchedule
	}
	sched, err := ParseSchedule(expr)
	if err != nil {
		return false, err
	}
	base := s.start
	last, err := s.DB.TaskRun.Query().Where(taskrun.TaskIDEQ(t.ID)).
		Order(ent.Desc(taskrun.FieldStartedAt)).First(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return false, err
	}
	if last != nil {
		base = last.StartedAt
	}
	return !sched.Next(base).After(now), nil
}

// fire 每个目标组一个会话。空组不跑；上一轮还在跑的组跳过本轮，不叠加。
func (s *Scheduler) fire(ctx context.Context, t *ent.Task) {
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
	model := t.Model
	if model == "" {
		model = s.DefaultModel
	}
	for _, g := range groups {
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
		run, session, err := s.begin(ctx, t, g, model)
		if err != nil {
			slog.Error("创建任务运行失败", "task", t.ID, "group", g.Name, "err", err)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.execute(ctx, t, g, run, session)
		}()
	}
}

func (s *Scheduler) begin(ctx context.Context, t *ent.Task, g *ent.Group, model string) (*ent.TaskRun, *ent.AgentSession, error) {
	tx, err := s.DB.Tx(ctx)
	if err != nil {
		return nil, nil, err
	}
	session, err := tx.AgentSession.Create().
		SetKind("task").SetGroupID(g.ID).SetInitiator(Initiator).SetModel(model).
		SetTitle(t.Name).SetDryRun(t.DryRun).
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		return nil, nil, err
	}
	run, err := tx.TaskRun.Create().
		SetTaskID(t.ID).SetGroupID(g.ID).SetSessionID(session.ID).
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		return nil, nil, err
	}
	return run, session, tx.Commit()
}

func (s *Scheduler) execute(ctx context.Context, t *ent.Task, g *ent.Group, run *ent.TaskRun, session *ent.AgentSession) {
	runCtx, cancel := context.WithTimeout(ctx, s.Timeout)
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
	update := s.DB.TaskRun.UpdateOneID(run.ID).SetFinishedAt(time.Now()).SetStatus("succeeded")
	if err != nil {
		update.SetStatus("failed").SetError(err.Error())
	}
	if uerr := update.Exec(done); uerr != nil {
		slog.Error("保存任务运行终态失败", "run", run.ID, "err", uerr)
	}
	if err == nil {
		slog.Info("任务完成", "task", t.ID, "group", g.Name)
		s.pushReports(done, g, session)
		return
	}
	slog.Error("任务失败", "task", t.ID, "group", g.Name, "err", err)
	// 巡检失败不能悄无声息：没人看控制台时，Webhook 是唯一的信号
	if s.Notify != nil {
		text := fmt.Sprintf("组「%s」的任务运行失败：%v", g.Name, err)
		if s.LinkBase != "" {
			text += "\n" + s.LinkBase + "/?session=" + session.ID.String()
		}
		if nerr := s.Notify(done, "任务失败："+t.Name, text); nerr != nil {
			slog.Error("任务失败通知发送失败", "run", run.ID, "err", nerr)
		}
	}
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
		if s.LinkBase != "" {
			text += "\n" + s.LinkBase + "/api/agent-reports/" + r.ID.String() + "/html"
		}
		if err := s.Notify(ctx, r.Title, text); err != nil {
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
