package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/agentsession"
	"openxdr/server/ent/finding"
	"openxdr/server/ent/report"
	"openxdr/server/ent/sessionmessage"
	"openxdr/server/internal/agentchat"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
)

func mapAgentSessions(mux *http.ServeMux, db *ent.Client, service *agentchat.Service) {
	mux.HandleFunc("POST /api/agent-sessions", func(w http.ResponseWriter, r *http.Request) {
		if service == nil || service.Model == "" {
			http.Error(w, "Pi 未启用", 503)
			return
		}
		var body struct {
			GroupID  uuid.UUID `json:"groupId"`
			Title    string    `json:"title"`
			Subjects []string  `json:"subjects"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body) != nil || len(body.Title) > 200 {
			http.Error(w, "请求无效", 400)
			return
		}
		if !requireGroup(w, r, db, body.GroupID, "analyst") {
			return
		}
		if err := checkSubjects(r.Context(), db, body.GroupID, body.Subjects); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		create := db.AgentSession.Create().SetKind("chat").SetGroupID(body.GroupID).SetInitiator(auth.From(r.Context()).Username).SetModel(service.Model).SetTitle(body.Title).SetStatus("idle")
		if len(body.Subjects) > 0 {
			create.SetSubjects(body.Subjects)
		}
		session, err := create.Save(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(201)
		writeJSON(w, session)
	})
	mux.HandleFunc("GET /api/agent-sessions", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.URL.Query().Get("groupId"))
		if err != nil {
			http.Error(w, "groupId 必填", 400)
			return
		}
		if !requireGroup(w, r, db, id, "viewer") {
			return
		}
		rows, err := db.AgentSession.Query().Where(agentsession.GroupIDEQ(id)).Order(ent.Desc(agentsession.FieldCreatedAt)).Limit(100).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, rows)
	})
	mux.HandleFunc("GET /api/agent-sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		session, ok := getByPath(w, r, "id", "session", db.AgentSession.Get)
		if !ok {
			return
		}
		if !requireGroup(w, r, db, session.GroupID, "viewer") {
			return
		}
		writeJSON(w, session)
	})
	mux.HandleFunc("GET /api/agent-sessions/{id}/messages", func(w http.ResponseWriter, r *http.Request) {
		session, ok := getByPath(w, r, "id", "session", db.AgentSession.Get)
		if !ok {
			return
		}
		if !requireGroup(w, r, db, session.GroupID, "viewer") {
			return
		}
		after := 0
		if raw := r.URL.Query().Get("afterSeq"); raw != "" {
			var err error
			after, err = strconv.Atoi(raw)
			if err != nil || after < 0 {
				http.Error(w, "afterSeq 必须为非负整数", 400)
				return
			}
		}
		rows, err := db.SessionMessage.Query().Where(sessionmessage.SessionIDEQ(session.ID), sessionmessage.SeqGT(after)).Order(ent.Asc(sessionmessage.FieldSeq)).Limit(1000).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, rows)
	})
	mux.HandleFunc("POST /api/agent-sessions/{id}/messages", func(w http.ResponseWriter, r *http.Request) {
		if service == nil || service.Model == "" {
			http.Error(w, "Pi 未启用", 503)
			return
		}
		session, ok := getByPath(w, r, "id", "session", db.AgentSession.Get)
		if !ok {
			return
		}
		if !requireGroup(w, r, db, session.GroupID, "analyst") {
			return
		}
		u := auth.From(r.Context())
		if session.Initiator != u.Username {
			http.Error(w, "只能继续自己发起的会话", 403)
			return
		}
		if session.Status != "idle" {
			http.Error(w, "会话不处于 idle", 409)
			return
		}
		var body struct {
			Prompt string `json:"prompt"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&body) != nil || strings.TrimSpace(body.Prompt) == "" {
			http.Error(w, "prompt 必填且不超过 64 KiB", 400)
			return
		}
		// 运行在后台：请求只负责把会话切到 running，前端切页、断开都不影响；进度靠轮询会话与消息
		if err := service.Start(r.Context(), session.ID, u, body.Prompt); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		writeJSON(w, map[string]any{"id": session.ID})
	})
	// 停止：发起人或组 admin；只写停止请求，运行所在节点轮询到后收手，会话回到 idle 可接着问
	mux.HandleFunc("POST /api/agent-sessions/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		session, ok := getByPath(w, r, "id", "session", db.AgentSession.Get)
		if !ok {
			return
		}
		if !requireGroup(w, r, db, session.GroupID, "analyst") {
			return
		}
		u := auth.From(r.Context())
		if session.Initiator != u.Username && !auth.Allowed(auth.GroupRole(r.Context(), db, u, session.GroupID), "admin") {
			http.Error(w, "只能停止自己发起的会话", 403)
			return
		}
		if service == nil {
			http.Error(w, "Pi 未启用", 503)
			return
		}
		if err := service.Cancel(r.Context(), session.ID); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	// 沙箱原型：给会话发起人签发工具令牌，会话外的 Pi 凭它经 /api/sandbox/tool 调用本会话的工具
	mux.HandleFunc("POST /api/agent-sessions/{id}/sandbox-token", func(w http.ResponseWriter, r *http.Request) {
		session, ok := getByPath(w, r, "id", "session", db.AgentSession.Get)
		if !ok || !requireGroup(w, r, db, session.GroupID, "analyst") {
			return
		}
		u := auth.From(r.Context())
		if session.Initiator != u.Username {
			http.Error(w, "只能为自己发起的会话签发", 403)
			return
		}
		if service == nil {
			http.Error(w, "Pi 未启用", 503)
			return
		}
		token, expires, err := service.IssueSandboxToken(r.Context(), session, u)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		audit.Log(r.Context(), db, r, "sandbox_token_issued", session.ID.String(), "有效至 "+expires.Format(time.RFC3339))
		writeJSON(w, map[string]any{"token": token, "expiresAt": expires})
	})
	mux.HandleFunc("GET /api/agent-reports", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.URL.Query().Get("groupId"))
		if err != nil {
			http.Error(w, "groupId 必填", 400)
			return
		}
		if !requireGroup(w, r, db, id, "viewer") {
			return
		}
		rows, err := db.Report.Query().Where(report.GroupIDEQ(id)).Order(ent.Desc(report.FieldCreatedAt)).Limit(100).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, rows)
	})
	mux.HandleFunc("GET /api/agent-reports/{id}", func(w http.ResponseWriter, r *http.Request) {
		row, ok := getByPath(w, r, "id", "report", db.Report.Get)
		if !ok {
			return
		}
		if !requireGroup(w, r, db, row.GroupID, "viewer") {
			return
		}
		writeJSON(w, row)
	})
}

// checkSubjects 「交给 AI」绑定的对象：incident:<id> 或 finding:<id>，最多 10 个，必须都属于会话所在组。
// 组内角色已在调用前检查过，这里只防把别组的事件塞进本组会话。
func checkSubjects(ctx context.Context, db *ent.Client, group uuid.UUID, subjects []string) error {
	if len(subjects) > 10 {
		return errors.New("一次最多交给 AI 10 条")
	}
	var incidents, findings []uuid.UUID
	for _, s := range subjects {
		kind, raw, _ := strings.Cut(s, ":")
		id, err := uuid.Parse(raw)
		if err != nil || (kind != "incident" && kind != "finding") {
			return fmt.Errorf("无效的对象 %q", s)
		}
		if kind == "incident" {
			incidents = append(incidents, id)
		} else {
			findings = append(findings, id)
		}
	}
	if len(incidents) > 0 {
		groups, err := incidentGroups(ctx, db, incidents)
		if err != nil {
			return err
		}
		for _, id := range incidents {
			if g := groups[id]; g == nil || *g != group {
				return errors.New("所选事件不都属于当前组")
			}
		}
	}
	if len(findings) > 0 {
		n, err := db.Finding.Query().Where(finding.IDIn(findings...), finding.GroupIDEQ(group)).Count(ctx)
		if err != nil {
			return err
		}
		if n != len(findings) {
			return errors.New("所选待办不都属于当前组")
		}
	}
	return nil
}
