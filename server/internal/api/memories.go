package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entasset "openxdr/server/ent/asset"
	entmemory "openxdr/server/ent/memory"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/memories"
)

type memoryRow struct {
	ID        uuid.UUID  `json:"id"`
	GroupID   uuid.UUID  `json:"groupId"`
	AssetID   *uuid.UUID `json:"assetId"`
	Hostname  string     `json:"hostname,omitempty"`
	Content   string     `json:"content"`
	Source    string     `json:"source"`
	Author    string     `json:"author"`
	SessionID *uuid.UUID `json:"sessionId"`
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
}

// mapMemories 组内长期记忆：AI 在会话里记下的环境知识，人可以补充、改正和删除。人改过的即算人工记忆，AI 不能再删
func mapMemories(mux *http.ServeMux, db *ent.Client) {
	mux.HandleFunc("GET /api/memories", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		q := db.Memory.Query()
		if !s.all {
			q = q.Where(entmemory.GroupIDIn(s.groups...))
		}
		rows, err := q.Order(ent.Desc(entmemory.FieldUpdatedAt)).Limit(1000).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var ids []uuid.UUID
		for _, m := range rows {
			if m.AssetID != nil {
				ids = append(ids, *m.AssetID)
			}
		}
		names := map[uuid.UUID]string{}
		if len(ids) > 0 {
			assets, err := db.Asset.Query().Where(entasset.IDIn(ids...)).All(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			for _, a := range assets {
				names[a.ID] = a.Hostname
			}
		}
		out := make([]memoryRow, len(rows))
		for i, m := range rows {
			out[i] = memoryRow{m.ID, m.GroupID, m.AssetID, "", m.Content, m.Source, m.Author, m.SessionID, m.CreatedAt, m.UpdatedAt}
			if m.AssetID != nil {
				out[i].Hostname = names[*m.AssetID]
			}
		}
		writeJSON(w, out)
	})

	mux.HandleFunc("POST /api/memories", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			GroupID uuid.UUID  `json:"groupId"`
			AssetID *uuid.UUID `json:"assetId"`
			Content string     `json:"content"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "请求体不是合法 JSON", http.StatusBadRequest)
			return
		}
		content, err := memories.Clean(body.Content)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !requireGroup(w, r, db, body.GroupID, "analyst") {
			return
		}
		if body.AssetID != nil {
			ok, err := db.Asset.Query().Where(entasset.IDEQ(*body.AssetID), entasset.GroupIDEQ(body.GroupID)).Exist(r.Context())
			if err != nil || !ok {
				http.Error(w, "主机不在该组", http.StatusBadRequest)
				return
			}
		}
		n, err := db.Memory.Query().Where(entmemory.GroupIDEQ(body.GroupID)).Count(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if n >= memories.Max {
			http.Error(w, "本组记忆已满，先删掉过时的", http.StatusConflict)
			return
		}
		m, err := db.Memory.Create().SetGroupID(body.GroupID).SetNillableAssetID(body.AssetID).SetContent(content).
			SetSource("human").SetAuthor(auth.From(r.Context()).Username).Save(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, "memory_create", m.ID.String(), content)
		writeJSON(w, map[string]any{"id": m.ID})
	})

	mux.HandleFunc("PATCH /api/memories/{id}", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Content string `json:"content"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "请求体不是合法 JSON", http.StatusBadRequest)
			return
		}
		content, err := memories.Clean(body.Content)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		m, ok := getByPath(w, r, "id", "memory", db.Memory.Get)
		if !ok || !requireGroup(w, r, db, m.GroupID, "analyst") {
			return
		}
		if err := m.Update().SetContent(content).SetSource("human").SetAuthor(auth.From(r.Context()).Username).Exec(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, "memory_update", m.ID.String(), content)
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("DELETE /api/memories/{id}", func(w http.ResponseWriter, r *http.Request) {
		m, ok := getByPath(w, r, "id", "memory", db.Memory.Get)
		if !ok || !requireGroup(w, r, db, m.GroupID, "analyst") {
			return
		}
		if err := db.Memory.DeleteOne(m).Exec(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, "memory_delete", m.ID.String(), m.Content)
		w.WriteHeader(http.StatusNoContent)
	})
}
