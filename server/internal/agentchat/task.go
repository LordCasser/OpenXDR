package agentchat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"openxdr/server/ent/agentsession"
	"openxdr/server/ent/report"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/schedule"
)

var _ schedule.Runner = (*Service)(nil)

// RunTask 以系统身份跑一次定时任务会话，实现 schedule.Runner。会话由调度器建好；
// 这里只认 kind=task、initiator=system 且仍在 running 的会话。
// 轮数耗尽时先续一次只带 report 的收尾；截断、收尾后仍未结束或没交报告都算失败：
// 巡检不完整不能当成"一切正常"。
func (s *Service) RunTask(ctx context.Context, job schedule.Job) (retErr error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	session := job.Session
	if session.Kind != "task" || session.Initiator != commandgate.SystemActor || session.Status != "running" {
		return errors.New("不是待运行的任务会话")
	}
	defer func() {
		finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		update := s.DB.AgentSession.UpdateOneID(session.ID).Where(agentsession.StatusEQ("running")).ClearRunExpiresAt().SetStatus("succeeded").SetFinishedAt(time.Now())
		if retErr != nil {
			update.SetStatus("failed").SetError(retErr.Error())
		}
		if err := update.Exec(finish); err != nil && retErr == nil {
			retErr = fmt.Errorf("保存会话终态失败: %w", err)
		}
	}()
	if err := s.DB.AgentSession.UpdateOneID(session.ID).Where(agentsession.StatusEQ("running")).SetRunExpiresAt(expiry(ctx)).Exec(ctx); err != nil {
		return err
	}
	if err := s.checkBudget(ctx, session.GroupID); err != nil {
		return err
	}
	request, err := s.request(ctx, session, job.Prompt, nil)
	if err != nil {
		return err
	}
	seq := 0
	who := commandgate.Request{System: true, ApprovalTimeout: job.ApprovalTimeout}
	handle := func(ctx context.Context, name string, args json.RawMessage) (string, error) {
		// 每次调用重读会话，避免用拉起时的旧快照判权
		current, err := s.DB.AgentSession.Get(ctx, session.ID)
		if err != nil {
			return "", err
		}
		return s.tool(ctx, current, who, name, args)
	}
	record := s.recorder(session, &seq, nil)
	// 轮数或时间耗尽先收尾一次，收尾仍没正常结束或没交报告才算失败
	result, err := s.investigate(ctx, session, request, handle, record, &seq)
	if err != nil {
		return err
	}
	n, err := s.DB.Report.Query().Where(report.SessionIDEQ(session.ID)).Count(ctx)
	if err != nil {
		return err
	}
	// 收尾就是为了交报告：报告交上了、只是收尾的轮数在最后一句话前用完，不算失败，否则会白白整轮重跑
	if result.StopReason != "stop" && (result.StopReason != "max_turns" || n == 0) {
		return fmt.Errorf("会话未完整结束：%s", result.StopReason)
	}
	if n == 0 {
		return errors.New("会话结束但没有提交报告")
	}
	return nil
}
