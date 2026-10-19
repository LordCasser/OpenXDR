package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/group"
	entreport "openxdr/server/ent/report"
	"openxdr/server/ent/sessionmessage"
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
	// NextRun 按当前周期算的下一次运行时间；停用或周期写错时为空
	NextRun *time.Time `json:"nextRun"`
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
	// 这一轮交的报告与做了多少步（工具调用次数）
	ReportID    *uuid.UUID `json:"reportId"`
	ReportTitle *string    `json:"reportTitle"`
	Steps       int        `json:"steps"`
}

// toTaskRow 任务行，带按当前周期算出的下一次运行时间
func toTaskRow(t *ent.Task) taskRow {
	row := taskRow{ID: t.ID, Name: t.Name, Schedule: t.Schedule, CustomSchedule: t.CustomSchedule, Enabled: t.Enabled,
		Model: t.Model, TargetGroup: t.TargetGroup, Prompt: t.Prompt}
	spec := t.Schedule
	if t.CustomSchedule != nil {
		spec = *t.CustomSchedule
	}
	if sched, err := schedule.ParseSchedule(spec); err == nil && t.Enabled {
		next := sched.Next(time.Now())
		row.NextRun = &next
	}
	return row
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
			out[i] = toTaskRow(t)
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
		writeJSON(w, toTaskRow(t))
	})

	// 立即运行：只记请求时间，由集群单活的调度器在下一次检查时拉起，避免多节点各跑一份
	api.HandleFunc("POST /api/tasks/{id}/run", func(w http.ResponseWriter, r *http.Request) {
		t, err := db.Task.Query().Where(enttask.IDEQ(r.PathValue("id")), enttask.Removed(false)).Only(r.Context())
		if ent.IsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !t.Enabled {
			http.Error(w, "任务已停用，先启用再运行", http.StatusConflict)
			return
		}
		if err := db.Task.UpdateOneID(t.ID).SetRunRequestedAt(time.Now()).Exec(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, "task_run_requested", t.ID, "")
		w.WriteHeader(http.StatusAccepted)
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
		var sessions []uuid.UUID
		for _, x := range runs {
			if x.SessionID != nil {
				sessions = append(sessions, *x.SessionID)
			}
		}
		reports, err := db.Report.Query().Where(entreport.SessionIDIn(sessions...)).Order(ent.Asc(entreport.FieldCreatedAt)).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		reportOf := map[uuid.UUID]*ent.Report{}
		for _, rep := range reports {
			reportOf[rep.SessionID] = rep // 一轮交了多份时取最后一份
		}
		var steps []struct {
			SessionID uuid.UUID `json:"session_id"`
			Count     int       `json:"count"`
		}
		if err := db.SessionMessage.Query().Where(sessionmessage.SessionIDIn(sessions...), sessionmessage.RoleEQ("toolResult")).
			GroupBy(sessionmessage.FieldSessionID).Aggregate(ent.Count()).Scan(r.Context(), &steps); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		stepOf := map[uuid.UUID]int{}
		for _, s := range steps {
			stepOf[s.SessionID] = s.Count
		}
		out := make([]taskRunRow, len(runs))
		for i, x := range runs {
			out[i] = taskRunRow{ID: x.ID, TaskID: x.TaskID, GroupID: x.GroupID, SessionID: x.SessionID, StartedAt: x.StartedAt,
				FinishedAt: x.FinishedAt, Status: x.Status, Error: x.Error}
			if x.SessionID != nil {
				if rep := reportOf[*x.SessionID]; rep != nil {
					out[i].ReportID, out[i].ReportTitle = &rep.ID, &rep.Title
				}
				out[i].Steps = stepOf[*x.SessionID]
			}
		}
		writeJSON(w, out)
	})
}
