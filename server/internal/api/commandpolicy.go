package api

import (
	"encoding/json"
	"github.com/google/uuid"
	"net/http"
	"openxdr/server/ent"
	"openxdr/server/ent/approval"
	"openxdr/server/ent/commandpolicy"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/commandgate"
	"time"
)

func requireGroup(w http.ResponseWriter, r *http.Request, db *ent.Client, id uuid.UUID, role string) bool {
	u := auth.From(r.Context())
	if u == nil || !auth.Allowed(auth.GroupRole(r.Context(), db, u, id), role) {
		http.Error(w, "无组内权限", http.StatusForbidden)
		return false
	}
	if _, err := db.Group.Get(r.Context(), id); err != nil {
		http.Error(w, "组不存在", http.StatusNotFound)
		return false
	}
	return true
}

func mapCommandPolicy(mux *http.ServeMux, db *ent.Client, gate *commandgate.Gate) {
	mux.HandleFunc("GET /api/command-policies", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.URL.Query().Get("groupId"))
		if err != nil {
			http.Error(w, "groupId 必填", 400)
			return
		}
		if !requireGroup(w, r, db, id, "admin") {
			return
		}
		rows, err := db.CommandPolicy.Query().Where(commandpolicy.GroupIDEQ(id)).Order(ent.Asc(commandpolicy.FieldCreatedAt)).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, rows)
	})
	mux.HandleFunc("POST /api/command-policies", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			GroupID uuid.UUID `json:"groupId"`
			Origin  string    `json:"origin"`
			Pattern string    `json:"pattern"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&body) != nil {
			http.Error(w, "请求无效", 400)
			return
		}
		if !requireGroup(w, r, db, body.GroupID, "admin") {
			return
		}
		if body.Origin != "ai" && body.Origin != "human" {
			http.Error(w, "origin 必须为 ai 或 human", 400)
			return
		}
		if _, err := commandgate.Match(body.Pattern, ""); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		mode := commandpolicy.ModeAllow
		if body.Origin == "human" {
			mode = commandpolicy.ModeDeny
		}
		tx, err := db.Tx(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer tx.Rollback()
		row, err := tx.CommandPolicy.Create().SetGroupID(body.GroupID).SetOrigin(commandpolicy.Origin(body.Origin)).SetMode(mode).SetPattern(body.Pattern).Save(r.Context())
		if err == nil {
			err = tx.AuditLog.Create().SetUsername(auth.From(r.Context()).Username).SetAction("command_policy_created").SetTarget(row.ID.String()).SetDetail(body.Origin + ": " + body.Pattern).SetRemoteAddr(r.RemoteAddr).Exec(r.Context())
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, row)
	})
	mux.HandleFunc("DELETE /api/command-policies/{id}", func(w http.ResponseWriter, r *http.Request) {
		row, ok := getByPath(w, r, "id", "policy", db.CommandPolicy.Get)
		if !ok {
			return
		}
		if !requireGroup(w, r, db, row.GroupID, "admin") {
			return
		}
		err := withTx(r, db, func(tx *ent.Tx) error {
			if err := tx.CommandPolicy.DeleteOneID(row.ID).Exec(r.Context()); err != nil {
				return err
			}
			return tx.AuditLog.Create().SetUsername(auth.From(r.Context()).Username).SetAction("command_policy_deleted").SetTarget(row.ID.String()).SetDetail(row.Pattern).SetRemoteAddr(r.RemoteAddr).Exec(r.Context())
		})
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /api/approvals", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.URL.Query().Get("groupId"))
		if err != nil {
			http.Error(w, "groupId 必填", 400)
			return
		}
		if !requireGroup(w, r, db, id, "admin") {
			return
		}
		// 重启遗留的请求也按截止时间失效；过期批准无法消费。
		_, err = db.Approval.Update().Where(approval.GroupIDEQ(id), approval.StatusIn(approval.StatusPending, approval.StatusApproved), approval.ExpiresAtLTE(time.Now())).SetStatus(approval.StatusExpired).Save(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		rows, err := db.Approval.Query().Where(approval.GroupIDEQ(id)).Order(ent.Desc(approval.FieldCreatedAt)).Limit(100).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, rows)
	})
	mux.HandleFunc("POST /api/approvals/{id}/decision", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "id 无效", 400)
			return
		}
		var body struct {
			Approve *bool `json:"approve"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body) != nil || body.Approve == nil {
			http.Error(w, "approve 必填", 400)
			return
		}
		row, err := db.Approval.Get(r.Context(), id)
		if err != nil {
			http.Error(w, "审批不存在", 404)
			return
		}
		if !requireGroup(w, r, db, row.GroupID, "admin") {
			return
		}
		if err := gate.Decide(r.Context(), id, auth.From(r.Context()), *body.Approve); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		w.WriteHeader(204)
	})
}
