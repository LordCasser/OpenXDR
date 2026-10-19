package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entevent "openxdr/server/ent/event"
	"openxdr/server/internal/aijob"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/eventai"
	"openxdr/server/internal/triage"
)

type relatedGroup struct {
	Relation string     `json:"relation"`
	Events   []eventRow `json:"events"`
}

// EventAIPaths 只挂这几个精确路径：挂 /api/events/ 子树会让 ServeMux 把 /api/events 重定向进子树，日志检索就没了
var EventAIPaths = []string{"GET /api/events/{id}/related", "GET /api/events/{id}/explain", "POST /api/events/{id}/explain"}

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

	// 解读在后台跑：POST 发起（已有在跑的或已有结果就直接返回它，refresh=1 才重来），GET 读当前这次。
	// 结果按发起人存：候选是按调用者能看的范围捞的，别人的解读可能提到他看不到的主机
	// 每个节点同时最多几次后台解读：调用不再挂在请求上，没有名额就能被连点拉起任意多次
	slots := make(chan struct{}, 4)
	key := func(r *http.Request) aijob.Key {
		return aijob.Key{Kind: "explain", Subject: r.PathValue("id"), Variant: r.URL.Query().Get("lang"), Owner: auth.From(r.Context()).ID.String()}
	}
	mux.HandleFunc("GET /api/events/{id}/explain", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireScope(w, r, db, "viewer"); !ok {
			return
		}
		j, err := aijob.Latest(r.Context(), db, key(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, aijob.ViewOf(j))
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
		k := key(r)
		prev, err := aijob.Latest(r.Context(), db, k)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if aijob.Running(prev) || (prev != nil && prev.Status == "done" && r.URL.Query().Get("refresh") != "1") {
			writeJSON(w, aijob.ViewOf(prev))
			return
		}
		host := map[string]any{}
		if e.AssetID != nil {
			if a, err := db.Asset.Get(r.Context(), *e.AssetID); err == nil {
				host = map[string]any{"hostname": a.Hostname, "os": a.Os, "ips": a.IPAddrs, "role": a.Role, "summary": a.Summary}
			}
		}
		select {
		case slots <- struct{}{}:
		default:
			http.Error(w, "解读繁忙，请稍后重试", http.StatusTooManyRequests)
			return
		}
		system, user := eventai.Messages(e, host, groups, k.Variant)
		// 已有一次在跑（别的标签页或节点刚发起）时 Start 返回那一次，照样轮询它
		j, _, err := aijob.Start(r.Context(), db, k, func(ctx context.Context) (any, error) {
			reply, err := llm.Chat(ctx, []triage.Message{{Role: "system", Content: system}, {Role: "user", Content: user}}, nil)
			if err != nil {
				return nil, fmt.Errorf("模型调用失败：%w", err)
			}
			return eventai.Parse(reply.Content, groups)
		}, func() { <-slots })
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, aijob.ViewOf(j))
	})
	return mux
}

func toEventRow(e *ent.Event) eventRow {
	return eventRow{ID: e.ID, Ts: e.Ts, ClassUID: e.ClassUID, Source: e.Source, AssetID: e.AssetID, Username: e.Username, ConnTuple: e.ConnTuple, Raw: e.Raw}
}
