package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entcommand "openxdr/server/ent/command"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/response"
)

type commandRow struct {
	ID          uuid.UUID  `json:"id"`
	CreatedAt   time.Time  `json:"createdAt"`
	Kind        string     `json:"kind"`
	Status      string     `json:"status"`
	DryRun      bool       `json:"dryRun"`
	AssetID     uuid.UUID  `json:"assetId"`
	IncidentID  *uuid.UUID `json:"incidentId"`
	IssuedBy    string     `json:"issuedBy"`
	Detail      *string    `json:"detail"`
	CompletedAt *time.Time `json:"completedAt"`
	Cmd         *string    `json:"cmd,omitempty"`
	ExitCode    *int32     `json:"exitCode,omitempty"`
	Stdout      *string    `json:"stdout,omitempty"`
	Stderr      *string    `json:"stderr,omitempty"`
	Truncated   bool       `json:"truncated,omitempty"`
}

func toRow(c *ent.Command) commandRow {
	return commandRow{
		ID: c.ID, CreatedAt: c.CreatedAt, Kind: c.Kind, Status: c.Status,
		DryRun: c.DryRun, AssetID: c.AssetID, IncidentID: c.IncidentID,
		IssuedBy: c.IssuedBy, Detail: c.Detail, CompletedAt: c.CompletedAt,
		Cmd: c.Cmd, ExitCode: c.ExitCode, Stdout: c.Stdout, Stderr: c.Stderr, Truncated: c.Truncated,
	}
}

type issueBody struct {
	Kind string `json:"kind"`
	// 指针以便区分"没传"和"显式传 false"：没传一律按 dry-run 处理
	DryRun      *bool      `json:"dryRun"`
	AssetID     uuid.UUID  `json:"assetId"`
	IncidentID  *uuid.UUID `json:"incidentId"`
	ProcessGUID *uuid.UUID `json:"processGuid"`
	PID         uint32     `json:"pid"`
	Cmd         string     `json:"cmd"`
	TimeoutMS   uint32     `json:"timeoutMs"`
}

func mapCommands(api *http.ServeMux, db *ent.Client, hub *response.Hub, selfEndpoints []string, gate *commandgate.Gate) {
	api.HandleFunc("POST /api/commands", func(w http.ResponseWriter, r *http.Request) {
		var body issueBody
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "请求体不是合法 JSON", http.StatusBadRequest)
			return
		}
		if _, ok := response.Kinds[body.Kind]; !ok {
			http.Error(w, "kind 必须是 kill_process / isolate_host / unisolate_host / exec", http.StatusBadRequest)
			return
		}
		if body.Kind == "exec" && body.Cmd == "" {
			http.Error(w, "exec 必须带 cmd", http.StatusBadRequest)
			return
		}
		// 处置要在目标主机所在组里有 analyst
		if !assetInScope(w, r, db, body.AssetID, "analyst") {
			return
		}
		// 不传就是演练。真执行必须显式写明，绝不默认动手
		dryRun := true
		if body.DryRun != nil {
			dryRun = *body.DryRun
		}

		req := response.Request{
			AssetID:     body.AssetID,
			Kind:        body.Kind,
			DryRun:      dryRun,
			IncidentID:  body.IncidentID,
			ProcessGUID: body.ProcessGUID,
			PID:         body.PID,
			IssuedBy:    audit.Actor(r.Context()),
			TimeoutMS:   body.TimeoutMS,
		}
		if body.Kind == "exec" {
			req.Cmd = &body.Cmd
		}
		// 隔离必须放行 server 自身，否则 agent 失联后再也解除不了
		if body.Kind == "isolate_host" {
			req.AllowEndpoints = selfEndpoints
		}

		var cmd *ent.Command
		var err error
		if body.Kind == "exec" {
			a, e := db.Asset.Get(r.Context(), body.AssetID)
			if e != nil || a.GroupID == nil {
				http.Error(w, "exec 资产必须归组", http.StatusConflict)
				return
			}
			u := auth.From(r.Context())
			if u == nil {
				http.Error(w, "未认证", http.StatusUnauthorized)
				return
			}
			cmd, err = gate.Issue(r.Context(), commandgate.Request{UserID: u.ID, GroupID: *a.GroupID, Origin: "human", Command: req})
		} else {
			cmd, err = hub.Issue(r.Context(), req)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		mode := "live"
		if dryRun {
			mode = "dry-run"
		}
		detail := body.Kind + " (" + mode + ")"
		if body.Kind == "exec" {
			detail += ": " + body.Cmd
		}
		audit.Log(r.Context(), db, r, "command_issued", cmd.ID.String(), detail)
		w.WriteHeader(http.StatusAccepted)
		writeJSON(w, toRow(cmd))
	})

	api.HandleFunc("GET /api/commands/{id}", func(w http.ResponseWriter, r *http.Request) {
		cmd, ok := getByPath(w, r, "id", "command", db.Command.Get)
		if !ok {
			return
		}
		asset, err := db.Asset.Get(r.Context(), cmd.AssetID)
		if err != nil {
			http.Error(w, "资产不存在", 404)
			return
		}
		if asset.GroupID != nil {
			if !requireGroup(w, r, db, *asset.GroupID, "viewer") {
				return
			}
		} else if u := auth.From(r.Context()); u == nil || u.Role != "admin" {
			http.Error(w, "无未分组资产权限", 403)
			return
		}
		writeJSON(w, toRow(cmd))
	})
	api.HandleFunc("GET /api/commands", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		q := db.Command.Query().Where(s.command()...)
		if v := r.URL.Query().Get("incidentId"); v != "" {
			id, err := uuid.Parse(v)
			if err != nil {
				http.Error(w, "无效的 incidentId", http.StatusBadRequest)
				return
			}
			q = q.Where(entcommand.IncidentIDEQ(id))
		}
		if v := r.URL.Query().Get("assetId"); v != "" {
			id, err := uuid.Parse(v)
			if err != nil {
				http.Error(w, "无效的 assetId", http.StatusBadRequest)
				return
			}
			q = q.Where(entcommand.AssetIDEQ(id))
		}
		cmds, err := q.Order(ent.Desc(entcommand.FieldCreatedAt)).Limit(100).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]commandRow, len(cmds))
		for i, c := range cmds {
			out[i] = toRow(c)
		}
		writeJSON(w, out)
	})
}
