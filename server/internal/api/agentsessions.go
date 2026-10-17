package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/agentsession"
	"openxdr/server/ent/report"
	"openxdr/server/ent/sessionmessage"
	"openxdr/server/internal/agentchat"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/piruntime"
)

func mapAgentSessions(mux *http.ServeMux, db *ent.Client, service *agentchat.Service) {
	mux.HandleFunc("POST /api/agent-sessions", func(w http.ResponseWriter, r *http.Request) {
		if service == nil || service.Model == "" {
			http.Error(w, "Pi 未启用", 503)
			return
		}
		var body struct {
			GroupID uuid.UUID `json:"groupId"`
			Title   string    `json:"title"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body) != nil || len(body.Title) > 200 {
			http.Error(w, "请求无效", 400)
			return
		}
		if !requireGroup(w, r, db, body.GroupID, "analyst") {
			return
		}
		session, err := db.AgentSession.Create().SetKind("chat").SetGroupID(body.GroupID).SetInitiator(auth.From(r.Context()).Username).SetModel(service.Model).SetTitle(body.Title).SetStatus("idle").Save(r.Context())
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
		if _, ok := w.(http.Flusher); !ok {
			http.Error(w, "SSE 不可用", 500)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		var mu sync.Mutex
		send := func(event string, value any) error {
			data, err := json.Marshal(value)
			if err != nil {
				return err
			}
			mu.Lock()
			defer mu.Unlock()
			controller := http.NewResponseController(w)
			_ = controller.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err == nil {
				err = controller.Flush()
			}
			_ = controller.SetWriteDeadline(time.Time{})
			if err != nil {
				cancel()
			}
			return err
		}
		if send("session", map[string]any{"id": session.ID}) != nil {
			return
		}
		done := make(chan struct{})
		defer func() { cancel(); <-done }()
		go func() {
			defer close(done)
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if send("heartbeat", struct{}{}) != nil {
						return
					}
				}
			}
		}()
		result, err := service.Chat(ctx, session.ID, u, body.Prompt, func(ctx context.Context, event piruntime.Event) error { return send("pi", event) })
		if err != nil {
			_ = send("error", map[string]string{"error": err.Error()})
			return
		}
		_ = send("done", result)
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
