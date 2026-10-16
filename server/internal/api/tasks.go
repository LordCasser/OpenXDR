package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/group"
	enttask "openxdr/server/ent/task"
	"openxdr/server/ent/taskrun"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/schedule"
)

type taskRow struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Schedule       string  `json:"schedule"`
	CustomSchedule *string `json:"customSchedule"`
	Enabled        bool    `json:"enabled"`
	Model          string  `json:"model"`
	TargetGroup    string  `json:"targetGroup"`
	Prompt         string  `json:"prompt"`
}

type taskRunRow struct {
	ID         uuid.UUID  `json:"id"`
	TaskID     string     `json:"taskId"`
	GroupID    uuid.UUID  `json:"groupId"`
	SessionID  *uuid.UUID `json:"sessionId"`
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt"`
	Status     string     `json:"status"`
	Error      *string    `json:"error"`
}

// mapTasks 预设任务：定义来自仓库 YAML，界面只能启停与改周期。
func mapTasks(api *http.ServeMux, db *ent.Client) {
	api.HandleFunc("GET /api/tasks", func(w http.ResponseWriter, r *http.Request) {
		scope, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		q := db.Task.Query().Where(enttask.Removed(false))
		if !scope.all {
			groups, err := db.Group.Query().Where(group.IDIn(scope.groups...)).All(r.Context())
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			names := make([]string, 0, len(groups)+1)
			if len(groups) > 0 {
				names = append(names, "*")
			}
			for _, g := range groups {
				names = append(names, g.Name)
			}
			q = q.Where(enttask.TargetGroupIn(names...))
		}
		tasks, err := q.Order(ent.Asc(enttask.FieldID)).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]taskRow, len(tasks))
		for i, t := range tasks {
			out[i] = taskRow{t.ID, t.Name, t.Schedule, t.CustomSchedule, t.Enabled, t.Model, t.TargetGroup, t.Prompt}
		}
		writeJSON(w, out)
	})

	// customSchedule 传空串表示恢复 YAML 里的周期
	api.HandleFunc("PATCH /api/tasks/{id}", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Enabled        *bool   `json:"enabled"`
			CustomSchedule *string `json:"customSchedule"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "请求体不是合法 JSON", http.StatusBadRequest)
			return
		}
		u := db.Task.UpdateOneID(r.PathValue("id")).Where(enttask.Removed(false))
		if body.Enabled != nil {
			u.SetEnabled(*body.Enabled)
		}
		if c := body.CustomSchedule; c != nil {
			if *c == "" {
				u.ClearCustomSchedule()
			} else if _, err := schedule.ParseSchedule(*c); err != nil {
				http.Error(w, "customSchedule 无效: "+err.Error(), http.StatusBadRequest)
				return
			} else {
				u.SetCustomSchedule(*c)
			}
		}
		t, err := u.Save(r.Context())
		if ent.IsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		detail, _ := json.Marshal(body)
		audit.Log(r.Context(), db, r, "task_updated", t.ID, string(detail))
		writeJSON(w, taskRow{t.ID, t.Name, t.Schedule, t.CustomSchedule, t.Enabled, t.Model, t.TargetGroup, t.Prompt})
	})

	// 运行记录按组裁剪：只看得到自己所在组的运行
	api.HandleFunc("GET /api/tasks/{id}/runs", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		q := db.TaskRun.Query().Where(taskrun.TaskIDEQ(r.PathValue("id")))
		if !s.all {
			q = q.Where(taskrun.GroupIDIn(s.groups...))
		}
		runs, err := q.Order(ent.Desc(taskrun.FieldStartedAt)).Limit(100).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]taskRunRow, len(runs))
		for i, x := range runs {
			out[i] = taskRunRow{x.ID, x.TaskID, x.GroupID, x.SessionID, x.StartedAt, x.FinishedAt, x.Status, x.Error}
		}
		writeJSON(w, out)
	})
}
