package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	entasset "openxdr/server/ent/asset"
	"openxdr/server/ent/incident"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/incidentstate"
	"openxdr/server/internal/sigma"
)

// batchResolveMax 一次批量结案的上限：再多就该先想想是不是该加抑制，而不是一口气关掉
const batchResolveMax = 200

// groupScanMax 归并视图最多扫最近这么多个事件，超出时响应头标 X-Truncated
const groupScanMax = 2000

// incidentGroup 按「主告警的规则 + 主机」归并的一组事件。归并只是视图，不改 incident 本身。
// 主告警取事件里级别最高的告警（同级取最早），情报命中的规则 ID 形如 intel:ip:1.2.3.4，同一目标自然归到一组
type incidentGroup struct {
	Key       string     `json:"key"`
	RuleID    string     `json:"ruleId"`
	RuleTitle *string    `json:"ruleTitle"`
	AssetID   *uuid.UUID `json:"assetId"`
	Hostname  *string    `json:"hostname"`
	Count     int        `json:"count"`
	Severity  int16      `json:"severity"`
	FirstAt   time.Time  `json:"firstAt"`
	LastAt    time.Time  `json:"lastAt"`
	// AI 研判分布：benign / suspicious / malicious / none（未研判或结论缺字段）
	Verdicts  map[string]int    `json:"verdicts"`
	Incidents []incidentSummary `json:"incidents"`
}

// verdictOf 研判结论，认不出的一律算未研判
func verdictOf(raw json.RawMessage) string {
	var v struct {
		Verdict string `json:"verdict"`
	}
	if json.Unmarshal(raw, &v) == nil && slices.Contains([]string{"benign", "suspicious", "malicious"}, v.Verdict) {
		return v.Verdict
	}
	return "none"
}

// listIncidentGroups 待复核 / 未结案事件按规则 + 主机归并
func listIncidentGroups(db *ent.Client, rules sigma.Catalog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := r.URL.Query().Get("status")
		if status == "" {
			status = "review"
		}
		// 归并是为了批量结案，已结案的不参与
		if status != "review" && status != "unresolved" {
			http.Error(w, "status 只能是 review / unresolved", http.StatusBadRequest)
			return
		}
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		q := filterIncidentStatus(db.Incident.Query().Where(s.incident()...), status)
		total, err := q.Clone().Count(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		incidents, err := q.Order(ent.Desc(incident.FieldCreatedAt)).Limit(groupScanMax).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ids := make([]uuid.UUID, len(incidents))
		for i, inc := range incidents {
			ids[i] = inc.ID
		}
		// 按 (incident, 规则, 主机) 聚合，行数随规则与主机数增长，不随告警量膨胀
		var rows []struct {
			IncidentID uuid.UUID  `json:"incident_id"`
			RuleID     string     `json:"rule_id"`
			AssetID    *uuid.UUID `json:"asset_id"`
			Count      int        `json:"count"`
			Max        int16      `json:"max"`
			Min        time.Time  `json:"min"`
		}
		err = db.Alert.Query().
			Where(alert.IncidentIDIn(ids...)).
			GroupBy(alert.FieldIncidentID, alert.FieldRuleID, alert.FieldAssetID).
			Aggregate(ent.Count(), ent.Max(alert.FieldSeverity), ent.Min(alert.FieldTs)).
			Scan(r.Context(), &rows)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		type primary struct {
			rule  string
			asset *uuid.UUID
			sev   int16
			first time.Time
			count int
		}
		primaryOf := map[uuid.UUID]*primary{}
		var assetIDs []uuid.UUID
		for _, row := range rows {
			p := primaryOf[row.IncidentID]
			if p == nil {
				p = &primary{sev: -1}
				primaryOf[row.IncidentID] = p
			}
			p.count += row.Count
			if row.Max > p.sev || row.Max == p.sev && row.Min.Before(p.first) {
				p.rule, p.asset, p.sev, p.first = row.RuleID, row.AssetID, row.Max, row.Min
			}
			if row.AssetID != nil {
				assetIDs = append(assetIDs, *row.AssetID)
			}
		}
		groupBy, err := incidentGroups(r.Context(), db, ids)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		assets, err := db.Asset.Query().Where(entasset.IDIn(assetIDs...)).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		hostOf := map[uuid.UUID]string{}
		for _, a := range assets {
			hostOf[a.ID] = a.Hostname
		}

		byKey := map[string]*incidentGroup{}
		var out []*incidentGroup
		for _, inc := range incidents {
			// 没有告警的事件（极少见）也要露出来，归到空规则下，不能从待办里凭空消失
			p := primaryOf[inc.ID]
			if p == nil {
				p = &primary{}
			}
			key := p.rule + "|"
			if p.asset != nil {
				key += p.asset.String()
			}
			g := byKey[key]
			if g == nil {
				g = &incidentGroup{Key: key, RuleID: p.rule, AssetID: p.asset, Verdicts: map[string]int{}, FirstAt: inc.CreatedAt, LastAt: inc.CreatedAt}
				if title := rules.TitleOf(p.rule); title != "" {
					g.RuleTitle = &title
				}
				if p.asset != nil {
					if h, ok := hostOf[*p.asset]; ok {
						g.Hostname = &h
					}
				}
				byKey[key] = g
				out = append(out, g)
			}
			sum := summarize(inc, p.count, max(p.sev, 0))
			sum.GroupID = groupBy[inc.ID]
			g.Incidents = append(g.Incidents, sum)
			g.Count++
			g.Severity = max(g.Severity, sum.Severity)
			g.Verdicts[verdictOf(inc.AiVerdict)]++
			if inc.CreatedAt.Before(g.FirstAt) {
				g.FirstAt = inc.CreatedAt
			}
			if inc.CreatedAt.After(g.LastAt) {
				g.LastAt = inc.CreatedAt
			}
		}
		// 反复出现的排前面，同数量按最近时间
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].Count != out[j].Count {
				return out[i].Count > out[j].Count
			}
			return out[i].LastAt.After(out[j].LastAt)
		})
		w.Header().Set("X-Total-Count", strconv.Itoa(total))
		if total > len(incidents) {
			w.Header().Set("X-Truncated", "1")
		}
		writeJSON(w, out)
	}
}

// resolveIncidents 批量结案：一个事务内全部成功或全部不动，逐条写审计。
// 口径与单个结案一致（resolutionOf）；任一事件不可见、已结案、需要理由却没写，整批拒绝，不做部分结案。
// AI 判恶意的事件按误报关必须显式 confirmMalicious，免得被一批良性顺手带走
func resolveIncidents(db *ent.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			IDs              []uuid.UUID `json:"ids"`
			Status           string      `json:"status"`
			Note             string      `json:"note"`
			ConfirmMalicious bool        `json:"confirmMalicious"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Status != "closed" && body.Status != "false_positive" {
			http.Error(w, "status 必须是 closed / false_positive，ids 为事件 ID 列表", http.StatusBadRequest)
			return
		}
		slices.SortFunc(body.IDs, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
		ids := slices.Compact(body.IDs)
		if len(ids) == 0 || len(ids) > batchResolveMax {
			http.Error(w, fmt.Sprintf("一次结案 1–%d 个事件", batchResolveMax), http.StatusBadRequest)
			return
		}
		note := strings.TrimSpace(body.Note)
		if utf8.RuneCountInString(note) > 2000 {
			http.Error(w, "结论备注最多 2000 字", http.StatusBadRequest)
			return
		}
		s, ok := requireScope(w, r, db, "analyst")
		if !ok {
			return
		}
		ctx := r.Context()
		tx, err := db.Tx(ctx)
		if err != nil {
			http.Error(w, "开启事务失败", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()
		// 锁住这批事件：并发的单个结案或引擎回写都得排队，不会出现结论被覆盖
		incs, err := tx.Incident.Query().
			Where(incident.IDIn(ids...)).Where(s.incident()...).
			Where(func(sel *sql.Selector) { sel.ForUpdate() }).
			All(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(incs) != len(ids) {
			if s.all {
				http.Error(w, fmt.Sprintf("有 %d 个事件不存在", len(ids)-len(incs)), http.StatusNotFound)
			} else {
				http.Error(w, "当前角色无此权限：部分事件不在你有分析权限的组内", http.StatusForbidden)
			}
			return
		}
		var resolved, malicious int
		proposals := map[string]bool{}
		for _, inc := range incs {
			if inc.Status != "open" && inc.Status != "triaged" {
				resolved++
			}
			if verdictOf(inc.AiVerdict) == "malicious" {
				malicious++
			}
			if p := inc.ClosureProposal; p != nil && strings.TrimSpace(p.Note) != "" {
				proposals[strings.TrimSpace(p.Note)] = true
			}
		}
		if resolved > 0 {
			http.Error(w, fmt.Sprintf("有 %d 个事件已被结案，请刷新后重选", resolved), http.StatusConflict)
			return
		}
		if body.Status == "false_positive" && malicious > 0 && !body.ConfirmMalicious {
			http.Error(w, fmt.Sprintf("其中 %d 个事件 AI 判恶意，按误报结案须二次确认", malicious), http.StatusConflict)
			return
		}
		user, remote, now := auth.From(ctx).Username, audit.RemoteAddr(r), time.Now()
		for _, inc := range incs {
			resolution, source, ok := resolutionOf(inc, body.Status, note)
			if !ok {
				http.Error(w, "有事件的结论与 AI 研判不一致或没有研判，须写明理由", http.StatusBadRequest)
				return
			}
			// 说明原样是这批里某个事件的 AI 结案建议：对其余事件同样是 AI 写的，不算人的独立判断
			if note != "" && proposals[note] {
				src := "ai_proposal"
				source = &src
			}
			err := tx.Incident.UpdateOneID(inc.ID).SetStatus(body.Status).ClearClosureProposal().
				SetResolution(resolution).SetNillableResolutionSource(source).
				SetResolvedBy(user).SetResolvedAt(now).Exec(ctx)
			if err == nil {
				err = incidentstate.Record(ctx, tx, inc.ID, incidentstate.StatusChanged, incidentstate.Origin{Kind: "user", ID: auth.From(ctx).ID.String()}, inc.Status)
			}
			if err == nil {
				err = audit.Checked(ctx, tx.AuditLog.Create(), user, remote, "incident_status", inc.ID.String(),
					strings.TrimSpace(fmt.Sprintf("%s %s", body.Status, note))+fmt.Sprintf("（批量结案 %d 个）", len(incs)))
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if err := tx.Commit(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]int{"resolved": len(incs)})
	}
}
