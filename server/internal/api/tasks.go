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
	NameEN         string  `json:"nameEn"`
	Description    string  `json:"description"`
	DescriptionEN  string  `json:"descriptionEn"`
	Category       string  `json:"category"`
	Schedule       string  `json:"schedule"`
	CustomSchedule *string `json:"customSchedule"`
	Enabled        bool    `json:"enabled"`
	// 按组开关：组 ID → 是否运行，没有的组跟 enabled 走；只含调用者能看到的组
	GroupEnabled map[string]bool `json:"groupEnabled"`
	Model        string          `json:"model"`
	TargetGroup  string          `json:"targetGroup"`
	Prompt       string          `json:"prompt"`
	// NextRuns 每个看得到且启用的组下一次开跑时间（计划时间加该组的错峰偏移）
	NextRuns map[string]time.Time `json:"nextRuns"`
	// NextRun NextRuns 里最早的一个；没有启用的组或周期写错时为空
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

// toTaskRow 任务行，带各组按当前周期与错峰偏移算出的下一次运行时间。
// visible 为 nil 表示能看全部组；groups 是要算下次运行时间的组（调用者看得到的）
func toTaskRow(t *ent.Task, visible map[uuid.UUID]bool, groups []*ent.Group) taskRow {
	row := taskRow{ID: t.ID, Name: t.Name, NameEN: t.NameEn, Description: t.Description, DescriptionEN: t.DescriptionEn, Category: t.Category,
		Schedule: t.Schedule, CustomSchedule: t.CustomSchedule, Enabled: t.Enabled, GroupEnabled: map[string]bool{},
		Model: t.Model, TargetGroup: t.TargetGroup, Prompt: t.Prompt, NextRuns: map[string]time.Time{}}
	for g, on := range t.GroupEnabled {
		if id, err := uuid.Parse(g); err == nil && (visible == nil || visible[id]) {
			row.GroupEnabled[g] = on
		}
	}
	spec := t.Schedule
	if t.CustomSchedule != nil {
		spec = *t.CustomSchedule
	}
	sched, err := schedule.ParseSchedule(spec)
	if err != nil {
		return row
	}
	now := time.Now()
	for _, g := range groups {
		if (t.TargetGroup != "*" && g.Name != t.TargetGroup) || !schedule.EnabledFor(t, g.ID) {
			continue
		}
		next := schedule.NextRun(sched, t.ID, g.ID, now)
		if next.IsZero() {
			continue
		}
		row.NextRuns[g.ID.String()] = next
		if row.NextRun == nil || next.Before(*row.NextRun) {
			row.NextRun = &next
		}
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
		gq := db.Group.Query()
		if !scope.all {
			gq = gq.Where(group.IDIn(scope.groups...))
		}
		groups, err := gq.All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if !scope.all {
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
		var visible map[uuid.UUID]bool
		if !scope.all {
			visible = map[uuid.UUID]bool{}
			for _, g := range scope.groups {
				visible[g] = true
			}
		}
		out := make([]taskRow, len(tasks))
		for i, t := range tasks {
			out[i] = toTaskRow(t, visible, groups)
		}
		writeJSON(w, out)
	})

	// 任务在某个组上的开关：enabled 为 true / false 覆盖全局默认，null 恢复跟随全局。组管理员即可设置
	api.HandleFunc("PUT /api/tasks/{id}/groups/{groupId}", func(w http.ResponseWriter, r *http.Request) {
		gid, err := uuid.Parse(r.PathValue("groupId"))
		if err != nil {
			http.Error(w, "组 ID 无效", http.StatusBadRequest)
			return
		}
		if !requireGroup(w, r, db, gid, "admin") {
			return
		}
		var body struct {
			Enabled *bool `json:"enabled"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "请求体不是合法 JSON", http.StatusBadRequest)
			return
		}
		t, err := db.Task.Query().Where(enttask.IDEQ(r.PathValue("id")), enttask.Removed(false)).Only(r.Context())
		if ent.IsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		g, err := db.Group.Get(r.Context(), gid)
		if err != nil || (t.TargetGroup != "*" && g.Name != t.TargetGroup) {
			http.Error(w, "这个任务不针对该组", http.StatusBadRequest)
			return
		}
		next := map[string]bool{}
		for k, v := range t.GroupEnabled {
			next[k] = v
		}
		if body.Enabled == nil {
			delete(next, gid.String())
		} else {
			next[gid.String()] = *body.Enabled
		}
		if t, err = db.Task.UpdateOneID(t.ID).SetGroupEnabled(next).Save(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		detail, _ := json.Marshal(map[string]any{"group": gid, "enabled": body.Enabled})
		audit.Log(r.Context(), db, r, "task_group_updated", t.ID, string(detail))
		writeJSON(w, toTaskRow(t, map[uuid.UUID]bool{gid: true}, []*ent.Group{g}))
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
		groups, err := db.Group.Query().All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, toTaskRow(t, nil, groups))
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
		if !schedule.AnyEnabled(t) {
			http.Error(w, "任务在所有组都未启用，先启用再运行", http.StatusConflict)
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
