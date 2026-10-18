package api

import (
	"net/http"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entevent "openxdr/server/ent/event"
	"openxdr/server/internal/eventai"
	"openxdr/server/internal/triage"
)

type relatedGroup struct {
	Relation string     `json:"relation"`
	Events   []eventRow `json:"events"`
}

// EventAIPaths 只挂这两个精确路径：挂 /api/events/ 子树会让 ServeMux 把 /api/events 重定向进子树，日志检索就没了
var EventAIPaths = []string{"GET /api/events/{id}/related", "POST /api/events/{id}/explain"}

// EventAI 日志检索里的「问 AI」：related 只查库给出确定关联的日志；explain 让模型读日志和这些候选，
// 给出解读并挑出相关的几条。两者都只在调用者能看的资产范围内取数
func EventAI(db *ent.Client, llm *triage.LLM) http.Handler {
	mux := http.NewServeMux()
	load := func(w http.ResponseWriter, r *http.Request) (*ent.Event, []eventai.Group, bool) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return nil, nil, false
		}
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "日志 ID 无效", http.StatusBadRequest)
			return nil, nil, false
		}
		e, err := db.Event.Query().Where(append(s.event(), entevent.IDEQ(id))...).Only(r.Context())
		if ent.IsNotFound(err) {
			http.Error(w, "日志不存在或无权查看", http.StatusNotFound)
			return nil, nil, false
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return nil, nil, false
		}
		groups, err := eventai.Related(r.Context(), db, s.event(), e)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return nil, nil, false
		}
		return e, groups, true
	}

	mux.HandleFunc("GET /api/events/{id}/related", func(w http.ResponseWriter, r *http.Request) {
		_, groups, ok := load(w, r)
		if !ok {
			return
		}
		out := make([]relatedGroup, len(groups))
		for i, g := range groups {
			out[i] = relatedGroup{Relation: g.Relation, Events: make([]eventRow, len(g.Events))}
			for j, e := range g.Events {
				out[i].Events[j] = toEventRow(e)
			}
		}
		writeJSON(w, out)
	})

	mux.HandleFunc("POST /api/events/{id}/explain", func(w http.ResponseWriter, r *http.Request) {
		if !llm.Enabled() {
			http.Error(w, "未配置研判与标注模型，无法解读", http.StatusServiceUnavailable)
			return
		}
		e, groups, ok := load(w, r)
		if !ok {
			return
		}
		host := map[string]any{}
		if e.AssetID != nil {
			if a, err := db.Asset.Get(r.Context(), *e.AssetID); err == nil {
				host = map[string]any{"hostname": a.Hostname, "os": a.Os, "ips": a.IPAddrs, "role": a.Role, "summary": a.Summary}
			}
		}
		system, user := eventai.Messages(e, host, groups, r.URL.Query().Get("lang"))
		reply, err := llm.Chat(r.Context(), []triage.Message{{Role: "system", Content: system}, {Role: "user", Content: user}}, nil)
		if err != nil {
			http.Error(w, "模型调用失败："+err.Error(), http.StatusBadGateway)
			return
		}
		x, err := eventai.Parse(reply.Content, groups)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, x)
	})
	return mux
}

func toEventRow(e *ent.Event) eventRow {
	return eventRow{ID: e.ID, Ts: e.Ts, ClassUID: e.ClassUID, Source: e.Source, AssetID: e.AssetID, Username: e.Username, ConnTuple: e.ConnTuple, Raw: e.Raw}
}
