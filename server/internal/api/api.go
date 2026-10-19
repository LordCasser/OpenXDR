// Package api 前端专用只读 API + 分析师状态操作。
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	entasset "openxdr/server/ent/asset"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/agentchat"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/review"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
)

// resolutionOf 结案说明与来源。人写了就用人的（原样是 AI 结案建议的，记为 ai_proposal）；
// 没写时只有结论与 AI 研判一致才行——判良性按误报关、判恶意或可疑按属实关——说明取研判摘要，记为 ai_verdict。
// 结论与研判相反正是最该写理由的时候，不能空着
func resolutionOf(inc *ent.Incident, status, note string) (string, *string, bool) {
	src := func(s string) *string { return &s }
	if note != "" {
		if p := inc.ClosureProposal; p != nil && note == strings.TrimSpace(p.Note) {
			return note, src("ai_proposal"), true
		}
		return note, nil, true
	}
	var v struct {
		Verdict string `json:"verdict"`
		Summary string `json:"summary"`
	}
	if json.Unmarshal(inc.AiVerdict, &v) != nil || v.Verdict == "" {
		return "", nil, false
	}
	agrees := status == "false_positive" && v.Verdict == "benign" ||
		status == "closed" && (v.Verdict == "malicious" || v.Verdict == "suspicious")
	if !agrees {
		return "", nil, false
	}
	summary := strings.TrimSpace(v.Summary)
	if summary == "" {
		summary = v.Verdict
	}
	return "采纳 AI 研判：" + summary, src("ai_verdict"), true
}

// triaged 是引擎专属状态，分析师只能在这三个之间拨
var analystStatuses = []string{"open", "closed", "false_positive"}

type incidentSummary struct {
	ID         uuid.UUID       `json:"id"`
	CreatedAt  time.Time       `json:"createdAt"`
	Status     string          `json:"status"`
	Title      *string         `json:"title"`
	AiVerdict  json.RawMessage `json:"aiVerdict"`
	AlertCount int             `json:"alertCount"`
	// 派生自告警的最高级别，列表按轻重着色用
	Severity int16 `json:"severity"`
	// 第一条有归属资产的告警所在资产的组，前端按组过滤/展示
	GroupID *uuid.UUID `json:"groupId"`
	// 结案信息：谁、何时、为什么
	Resolution *string    `json:"resolution"`
	ResolvedBy *string    `json:"resolvedBy"`
	ResolvedAt *time.Time `json:"resolvedAt"`
	// ClosureProposal AI 的结案建议，人采纳或忽略
	ClosureProposal *schema.ClosureProposal `json:"closureProposal"`
}

type alertRow struct {
	ID        uuid.UUID  `json:"id"`
	Ts        time.Time  `json:"ts"`
	LastTs    *time.Time `json:"lastTs"`
	Count     int        `json:"count"`
	Severity  int16      `json:"severity"`
	RuleID    string     `json:"ruleId"`
	RuleTitle *string    `json:"ruleTitle"`
	// RuleAuthor 规则作者：社区规则的许可要求命中展示时保留
	RuleAuthor string          `json:"ruleAuthor,omitempty"`
	Event      json.RawMessage `json:"event"`
	// 合成检测（心跳等）的依据，一行人读的话；规则命中为空
	Detail *string `json:"detail,omitempty"`
}

type incidentDetail struct {
	incidentSummary
	Graph json.RawMessage `json:"graph"`
	// 响应指令要下发到具体主机，取告警里第一个有归属的资产
	AssetID *uuid.UUID `json:"assetId"`
	Alerts  []alertRow `json:"alerts"`
}

func Handler(db *ent.Client, rules sigma.Catalog, hub *response.Hub, suppressions *suppress.Store, intelStore *intel.Store, selfEndpoints []string, chats ...*agentchat.Service) http.Handler {
	mux := http.NewServeMux()
	gate := &commandgate.Gate{DB: db, Hub: hub}
	var chat *agentchat.Service
	if len(chats) > 0 {
		chat = chats[0]
	}
	if chat != nil && chat.Gate != nil {
		gate = chat.Gate
	}
	mapCommands(mux, db, rules, hub, selfEndpoints, gate)
	mapCommandPolicy(mux, db, gate)
	mapAgentSessions(mux, db, chat)
	mapSuppressions(mux, db, suppressions, rules)
	mapIntel(mux, db, intelStore)
	mapStats(mux, db, rules)
	mapEvents(mux, db)
	mapRules(mux, rules)
	mapAttack(mux, rules)
	mapReport(mux, db, rules)
	mapAgentConfig(mux, db)
	mapUsers(mux, db)
	var queries queryProvisioner
	if chat != nil {
		queries, _ = chat.Query.(queryProvisioner)
	}
	mapGroups(mux, db, queries)
	mapTasks(mux, db)
	mapFindings(mux, db)
	mapMemories(mux, db)
	mapReportRender(mux, db)

	mux.HandleFunc("GET /api/incidents", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		q := db.Incident.Query().Where(s.incident()...)
		switch status := r.URL.Query().Get("status"); status {
		case "":
		case "unresolved":
			// 待处置：引擎已研判但分析师还没结案的也算
			q = q.Where(incident.StatusIn("open", "triaged"))
		case "review":
			// 需人工复核：与通知推送同一口径
			q = q.Where(review.Needed())
		default:
			q = q.Where(incident.StatusEQ(status))
		}
		// 资产详情页：涉及这台主机的事件
		if v := r.URL.Query().Get("assetId"); v != "" {
			id, err := uuid.Parse(v)
			if err != nil {
				http.Error(w, "无效的 assetId", http.StatusBadRequest)
				return
			}
			q = q.Where(incident.HasAlertsWith(alert.AssetIDEQ(id)))
		}
		limit := 50
		if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil {
			limit = min(max(n, 1), 500)
		}
		offset := 0
		if n, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && n > 0 {
			offset = n
		}
		total, err := q.Clone().Count(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		incidents, err := q.Order(ent.Desc(incident.FieldCreatedAt)).Limit(limit).Offset(offset).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		ids := make([]uuid.UUID, len(incidents))
		for i, inc := range incidents {
			ids[i] = inc.ID
		}
		var counts []struct {
			IncidentID uuid.UUID `json:"incident_id"`
			Count      int       `json:"count"`
			Max        int16     `json:"max"`
		}
		_ = db.Alert.Query().
			Where(alert.IncidentIDIn(ids...)).
			GroupBy(alert.FieldIncidentID).
			Aggregate(ent.Count(), ent.Max(alert.FieldSeverity)).
			Scan(r.Context(), &counts)
		countBy := map[uuid.UUID]int{}
		sevBy := map[uuid.UUID]int16{}
		for _, c := range counts {
			countBy[c.IncidentID] = c.Count
			sevBy[c.IncidentID] = c.Max
		}

		groupBy, err := incidentGroups(r.Context(), db, ids)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		out := make([]incidentSummary, len(incidents))
		for i, inc := range incidents {
			out[i] = summarize(inc, countBy[inc.ID], sevBy[inc.ID])
			out[i].GroupID = groupBy[inc.ID]
		}
		w.Header().Set("X-Total-Count", strconv.Itoa(total))
		writeJSON(w, out)
	})

	mux.HandleFunc("GET /api/incidents/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "无效的 incident id", http.StatusBadRequest)
			return
		}
		if !incidentVisible(w, r, db, id, "viewer") {
			return
		}
		inc, err := db.Incident.Get(r.Context(), id)
		if ent.IsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		alerts, err := db.Alert.Query().
			Where(alert.IncidentIDEQ(id)).
			Order(ent.Asc(alert.FieldTs)).
			Limit(500).
			WithEvent().
			All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var assetID *uuid.UUID
		var maxSev int16
		rows := make([]alertRow, len(alerts))
		for i, a := range alerts {
			if assetID == nil && a.AssetID != nil {
				assetID = a.AssetID
			}
			if a.Severity > maxSev {
				maxSev = a.Severity
			}
			row := alertRow{
				ID: a.ID, Ts: a.Ts, LastTs: a.LastTs, Count: a.Count,
				Severity: a.Severity, RuleID: a.RuleID, Detail: a.Detail,
			}
			if title := rules.TitleOf(a.RuleID); title != "" {
				row.RuleTitle = &title
			}
			row.RuleAuthor = rules.AuthorOf(a.RuleID)
			if a.Edges.Event != nil {
				row.Event = a.Edges.Event.Raw
			}
			rows[i] = row
		}
		groupBy, err := incidentGroups(r.Context(), db, []uuid.UUID{id})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		summary := summarize(inc, len(alerts), maxSev)
		summary.GroupID = groupBy[id]
		writeJSON(w, incidentDetail{
			incidentSummary: summary,
			Graph:           inc.Graph,
			AssetID:         assetID,
			Alerts:          rows,
		})
	})

	// 结案必须写结论备注：closed 属实已处置，false_positive 误报或良性；备注会作为案例喂回研判
	mux.HandleFunc("POST /api/incidents/{id}/status", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "无效的 incident id", http.StatusBadRequest)
			return
		}
		var body struct {
			Status string `json:"status"`
			Note   string `json:"note"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || !slices.Contains(analystStatuses, body.Status) {
			http.Error(w, "status 必须是 open / closed / false_positive", http.StatusBadRequest)
			return
		}
		note := strings.TrimSpace(body.Note)
		if utf8.RuneCountInString(note) > 2000 {
			http.Error(w, "结论备注最多 2000 字", http.StatusBadRequest)
			return
		}
		if !incidentVisible(w, r, db, id, "analyst") {
			return
		}
		inc, err := db.Incident.Get(r.Context(), id)
		if ent.IsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// 人改了状态，AI 的结案建议就作废了（采纳也走这里）
		u := db.Incident.UpdateOneID(id).SetStatus(body.Status).ClearClosureProposal()
		if body.Status == "open" {
			u.ClearResolution().ClearResolvedBy().ClearResolvedAt().ClearResolutionSource()
		} else {
			resolution, source, ok := resolutionOf(inc, body.Status, note)
			if !ok {
				http.Error(w, "结论与 AI 研判不一致或事件没有研判时，须写明理由", http.StatusBadRequest)
				return
			}
			u.SetResolution(resolution).SetNillableResolutionSource(source).
				SetResolvedBy(auth.From(r.Context()).Username).SetResolvedAt(time.Now())
		}
		err = u.Exec(r.Context())
		if ent.IsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, "incident_status", id.String(), strings.TrimSpace(body.Status+" "+note))
		w.WriteHeader(http.StatusNoContent)
	})

	// 忽略 AI 的结案建议
	mux.HandleFunc("DELETE /api/incidents/{id}/closure-proposal", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "无效的 incident id", http.StatusBadRequest)
			return
		}
		if !incidentVisible(w, r, db, id, "analyst") {
			return
		}
		if err := db.Incident.UpdateOneID(id).ClearClosureProposal().Exec(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, "incident_proposal_dismissed", id.String(), "")
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("GET /api/assets", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		assets, err := db.Asset.Query().Where(s.asset()...).Order(ent.Asc(entasset.FieldHostname)).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		type assetRow struct {
			ID        uuid.UUID  `json:"id"`
			Hostname  string     `json:"hostname"`
			Os        *string    `json:"os"`
			IPAddrs   []string   `json:"ipAddrs"`
			AgentID   *uuid.UUID `json:"agentId"`
			FirstSeen time.Time  `json:"firstSeen"`
			LastSeen  time.Time  `json:"lastSeen"`
			GroupID   *uuid.UUID `json:"groupId"`
			// 失联通知已发出时的起始时刻，前端据此标红
			SilentSince     *time.Time      `json:"silentSince"`
			AgentVersion    *string         `json:"agentVersion"`
			CollectorHealth json.RawMessage `json:"collectorHealth"`
		}
		out := make([]assetRow, len(assets))
		for i, a := range assets {
			out[i] = assetRow{a.ID, a.Hostname, a.Os, a.IPAddrs, a.AgentID, a.FirstSeen, a.LastSeen, a.GroupID, a.SilentSince, a.AgentVersion, a.CollectorHealth}
		}
		writeJSON(w, out)
	})

	return mux
}

func summarize(inc *ent.Incident, alertCount int, severity int16) incidentSummary {
	return incidentSummary{
		ID: inc.ID, CreatedAt: inc.CreatedAt, Status: inc.Status,
		Title: inc.Title, AiVerdict: inc.AiVerdict, AlertCount: alertCount,
		Severity: severity, Resolution: inc.Resolution, ResolvedBy: inc.ResolvedBy, ResolvedAt: inc.ResolvedAt,
		ClosureProposal: inc.ClosureProposal,
	}
}

// incidentGroups 各 incident 第一条有归属资产的告警所在资产的组。
// 按 (incident, 资产) 聚合最早时间，行数只随涉及的主机数增长，不随告警量膨胀。
func incidentGroups(ctx context.Context, db *ent.Client, ids []uuid.UUID) (map[uuid.UUID]*uuid.UUID, error) {
	var firsts []struct {
		IncidentID uuid.UUID `json:"incident_id"`
		AssetID    uuid.UUID `json:"asset_id"`
		Min        time.Time `json:"min"`
	}
	err := db.Alert.Query().
		Where(alert.IncidentIDIn(ids...), alert.AssetIDNotNil()).
		GroupBy(alert.FieldIncidentID, alert.FieldAssetID).
		Aggregate(ent.Min(alert.FieldTs)).
		Scan(ctx, &firsts)
	if err != nil {
		return nil, err
	}
	first := map[uuid.UUID]uuid.UUID{}
	earliest := map[uuid.UUID]time.Time{}
	assetIDs := make([]uuid.UUID, 0, len(firsts))
	for _, f := range firsts {
		if ts, ok := earliest[f.IncidentID]; !ok || f.Min.Before(ts) {
			earliest[f.IncidentID] = f.Min
			first[f.IncidentID] = f.AssetID
		}
		assetIDs = append(assetIDs, f.AssetID)
	}
	assets, err := db.Asset.Query().Where(entasset.IDIn(assetIDs...)).All(ctx)
	if err != nil {
		return nil, err
	}
	groupOf := map[uuid.UUID]*uuid.UUID{}
	for _, a := range assets {
		groupOf[a.ID] = a.GroupID
	}
	out := make(map[uuid.UUID]*uuid.UUID, len(first))
	for inc, asset := range first {
		out[inc] = groupOf[asset]
	}
	return out, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
