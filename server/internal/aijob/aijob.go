// Package aijob 把一次模型调用从 HTTP 请求里挪到后台：发起时落一行 running 立即返回，
// 跑完写回结果或错误，前端轮询。请求断开（换页、刷新、反代超时）不影响模型调用本身，
// 结果在库里，哪个节点都能读到。
package aijob

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entjob "openxdr/server/ent/aijob"
)

const (
	// 单次模型调用的上限；超过就记失败
	runTimeout = 5 * time.Minute
	// running 超过这个时间还没写回，只可能是跑它的进程没了（发版重启）
	staleAfter = runTimeout + time.Minute
)

// 各类结果保留多久：导入结果里有封存的凭据令牌，用完即走
var keep = map[string]time.Duration{"explain": 7 * 24 * time.Hour, "host_import": time.Hour}

// View 给前端的样子：status 取 none / running / done / failed
type View struct {
	ID         uuid.UUID      `json:"id,omitempty"`
	Status     string         `json:"status"`
	Result     map[string]any `json:"result,omitempty"`
	Error      string         `json:"error,omitempty"`
	CreatedAt  *time.Time     `json:"createdAt,omitempty"`
	FinishedAt *time.Time     `json:"finishedAt,omitempty"`
}

// Key 一个任务属于谁、针对什么
type Key struct{ Kind, Subject, Variant, Owner string }

// ViewOf 把一行变成 View；nil 表示还没跑过。卡在 running 太久的按被打断处理
func ViewOf(j *ent.AIJob) View {
	if j == nil {
		return View{Status: "none"}
	}
	v := View{ID: j.ID, Status: j.Status, Result: j.Result, Error: j.Error, CreatedAt: &j.CreatedAt, FinishedAt: j.FinishedAt}
	if j.Status == "running" && time.Since(j.CreatedAt) > staleAfter {
		v.Status, v.Error = "failed", "服务重启打断了这次调用，请重新发起"
	}
	return v
}

// Latest 这个对象最近一次任务，没有返回 nil
func Latest(ctx context.Context, db *ent.Client, k Key) (*ent.AIJob, error) {
	j, err := db.AIJob.Query().
		Where(entjob.KindEQ(k.Kind), entjob.SubjectEQ(k.Subject), entjob.VariantEQ(k.Variant), entjob.OwnerEQ(k.Owner),
			entjob.CreatedAtGT(time.Now().Add(-keep[k.Kind]))).
		Order(ent.Desc(entjob.FieldCreatedAt)).First(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	return j, err
}

// Running 这个对象是否已有一次在跑（没卡死的）
func Running(j *ent.AIJob) bool { return j != nil && ViewOf(j).Status == "running" }

// Start 落一行 running，后台跑 fn，结果按 JSON 存。release 在跑完后调用（释放并发名额），可为 nil
func Start(ctx context.Context, db *ent.Client, k Key, fn func(context.Context) (any, error), release func()) (*ent.AIJob, error) {
	prune(ctx, db)
	j, err := db.AIJob.Create().SetKind(k.Kind).SetSubject(k.Subject).SetVariant(k.Variant).SetOwner(k.Owner).Save(ctx)
	if err != nil {
		if release != nil {
			release()
		}
		return nil, err
	}
	go func() {
		if release != nil {
			defer release()
		}
		run, cancel := context.WithTimeout(context.Background(), runTimeout)
		defer cancel()
		out, err := fn(run)
		// 写回不跟着调用的超时走，免得模型刚好用满时间结果写不进去
		save, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		up := db.AIJob.UpdateOneID(j.ID).SetFinishedAt(time.Now())
		if err == nil {
			var m map[string]any
			if b, mErr := json.Marshal(out); mErr == nil && json.Unmarshal(b, &m) == nil {
				up.SetStatus("done").SetResult(m)
			} else {
				err = mErr
			}
		}
		if err != nil {
			up.SetStatus("failed").SetError(err.Error())
		}
		if sErr := up.Exec(save); sErr != nil {
			slog.Error("AI 任务结果写回失败", "kind", k.Kind, "job", j.ID, "err", sErr)
		}
	}()
	return j, nil
}

// Discard 删掉某人对某对象的任务（导入确认后，结果里的凭据令牌不再需要）
func Discard(ctx context.Context, db *ent.Client, k Key) error {
	_, err := db.AIJob.Delete().Where(entjob.KindEQ(k.Kind), entjob.SubjectEQ(k.Subject), entjob.OwnerEQ(k.Owner)).Exec(ctx)
	return err
}

func prune(ctx context.Context, db *ent.Client) {
	for kind, d := range keep {
		if _, err := db.AIJob.Delete().Where(entjob.KindEQ(kind), entjob.CreatedAtLT(time.Now().Add(-d))).Exec(ctx); err != nil {
			slog.Warn("清理过期 AI 任务失败", "kind", kind, "err", err)
		}
	}
}
