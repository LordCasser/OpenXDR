package api

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entasset "openxdr/server/ent/asset"
	"openxdr/server/ent/finding"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
)

type findingRow struct {
	ID         uuid.UUID  `json:"id"`
	GroupID    uuid.UUID  `json:"groupId"`
	AssetID    uuid.UUID  `json:"assetId"`
	Hostname   string     `json:"hostname"`
	Key        string     `json:"key"`
	Title      string     `json:"title"`
	Detail     string     `json:"detail"`
	Severity   string     `json:"severity"`
	Status     string     `json:"status"`
	FirstSeen  time.Time  `json:"firstSeen"`
	LastSeen   time.Time  `json:"lastSeen"`
	SessionID  *uuid.UUID `json:"sessionId"`
	ResolvedAt *time.Time `json:"resolvedAt"`
	ResolvedBy *string    `json:"resolvedBy"`
	Note       *string    `json:"note"`
}

// mapFindings 运维待办：巡检 AI 登记与复查，人在这里标记已处理或忽略。忽略的 AI 不再登记。
func mapFindings(mux *http.ServeMux, db *ent.Client) {
	mux.HandleFunc("GET /api/findings", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		q := db.Finding.Query()
		if !s.all {
			q = q.Where(finding.GroupIDIn(s.groups...))
		}
		if status := r.URL.Query().Get("status"); status != "" {
			q = q.Where(finding.StatusEQ(status))
		}
		rows, err := q.Order(ent.Desc(finding.FieldLastSeen)).Limit(500).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ids := make([]uuid.UUID, len(rows))
		for i, f := range rows {
			ids[i] = f.AssetID
		}
		assets, err := db.Asset.Query().Where(entasset.IDIn(ids...)).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		names := map[uuid.UUID]string{}
		for _, a := range assets {
			names[a.ID] = a.Hostname
		}
		out := make([]findingRow, len(rows))
		for i, f := range rows {
			out[i] = findingRow{f.ID, f.GroupID, f.AssetID, names[f.AssetID], f.Key, f.Title, f.Detail, f.Severity,
				f.Status, f.FirstSeen, f.LastSeen, f.SessionID, f.ResolvedAt, f.ResolvedBy, f.Note}
		}
		writeJSON(w, out)
	})

	// 已处理与忽略必须写原因：忽略原因会交给巡检 AI，已处理的下一轮仍会复查
	mux.HandleFunc("POST /api/findings/{id}/status", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "无效的待办 id", http.StatusBadRequest)
			return
		}
		var body struct {
			Status string `json:"status"`
			Note   string `json:"note"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || !slices.Contains([]string{"open", "resolved", "ignored"}, body.Status) {
			http.Error(w, "status 必须是 open / resolved / ignored", http.StatusBadRequest)
			return
		}
		note := strings.TrimSpace(body.Note)
		if body.Status != "open" && (note == "" || utf8.RuneCountInString(note) > 2000) {
			http.Error(w, "须写明原因（1–2000 字）", http.StatusBadRequest)
			return
		}
		f, err := db.Finding.Get(r.Context(), id)
		if ent.IsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !requireGroup(w, r, db, f.GroupID, "analyst") {
			return
		}
		u := f.Update().SetStatus(body.Status)
		if body.Status == "open" {
			u.ClearResolvedAt().ClearResolvedBy().ClearNote()
		} else {
			u.SetResolvedAt(time.Now()).SetResolvedBy(auth.From(r.Context()).Username).SetNote(note)
		}
		if err := u.Exec(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, "finding_status", f.Title, strings.TrimSpace(body.Status+" "+note))
		w.WriteHeader(http.StatusNoContent)
	})
}
