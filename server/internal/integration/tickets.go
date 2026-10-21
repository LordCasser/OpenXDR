package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/externalticket"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/integration"
	"openxdr/server/ent/integrationgroup"
	"openxdr/server/ent/integrationidempotency"
	"openxdr/server/ent/integrationtoken"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/incidentstate"
)

type ticketInput struct {
	URL    string `json:"url"`
	Status string `json:"status"`
	Title  string `json:"title"`
}
type ticketRow struct {
	ID            uuid.UUID `json:"id"`
	IntegrationID uuid.UUID `json:"integrationId"`
	IncidentID    uuid.UUID `json:"incidentId"`
	ExternalID    string    `json:"externalId"`
	URL           string    `json:"url"`
	Status        string    `json:"status"`
	Title         string    `json:"title"`
	UpdatedAt     time.Time `json:"updatedAt"`
	SourceDeleted bool      `json:"sourceDeleted"`
}

func TicketDTO(t *ent.ExternalTicket) any {
	return ticketRow{t.ID, t.IntegrationID, t.IncidentID, t.ExternalID, t.URL, t.Status, t.Title, t.UpdatedAt, t.SourceDeleted}
}
func readWriteBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(v) != nil || dec.Decode(new(any)) != io.EOF {
		Error(w, 400, "invalid_argument", "请求格式无效")
		return false
	}
	return true
}

// writeTransaction 在当前授权下锁住身份、令牌、事件与资产，幂等结果和审计随业务一起提交。
func (s *Service) writeTransaction(w http.ResponseWriter, r *http.Request, body any, scope string, apply func(*ent.Tx, *ent.Incident, *ent.Integration) (any, int, string)) {
	key := r.Header.Get("Idempotency-Key")
	if len(key) < 1 || len(key) > 200 || strings.TrimSpace(key) != key || strings.ContainsAny(key, "\r\n") {
		Error(w, 400, "invalid_argument", "Idempotency-Key 必填且最多 200 字节")
		return
	}
	if len(r.URL.Path) > 1024 || r.URL.RawQuery != "" {
		Error(w, 400, "invalid_argument", "写接口不接受查询参数")
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		Error(w, 404, "not_found", "事件不存在")
		return
	}
	p := r.Context().Value(principalKey{}).(principal)
	ctx := r.Context()
	tx, err := s.DB.Tx(ctx)
	if readError(w, err) {
		return
	}
	defer tx.Rollback()
	owner, err := tx.Integration.Query().Where(integration.IDEQ(p.Integration.ID)).Where(func(s *sql.Selector) { s.ForUpdate() }).Only(ctx)
	if readError(w, err) {
		return
	}
	token, err := tx.IntegrationToken.Query().Where(integrationtoken.IDEQ(p.Token.ID)).Where(func(s *sql.Selector) { s.ForUpdate() }).Only(ctx)
	if readError(w, err) {
		return
	}
	if !owner.Enabled || token.Revoked || !time.Now().Before(token.ExpiresAt) || !slices.Contains(owner.Scopes, scope) || !slices.Contains(token.Scopes, scope) {
		Error(w, 403, "forbidden", "授权已变化")
		return
	}
	grants, err := tx.IntegrationGroup.Query().Where(integrationgroup.IntegrationIDEQ(owner.ID)).All(ctx)
	if readError(w, err) {
		return
	}
	groups := []uuid.UUID{}
	for _, g := range grants {
		groups = append(groups, g.GroupID)
	}
	// 不存在与范围外同一应答，也不给范围外的行加锁；加锁后再判一次，挡住期间的移组
	if visible, err := tx.Incident.Query().Where(incident.IDEQ(id)).Where(incidentScope(groups)...).Exist(ctx); readError(w, err) {
		return
	} else if !visible {
		Error(w, 404, "not_found", "事件不存在")
		return
	}
	row, err := tx.Incident.Query().Where(incident.IDEQ(id)).Where(func(s *sql.Selector) { s.ForUpdate() }).Only(ctx)
	if ent.IsNotFound(err) {
		Error(w, 404, "not_found", "事件不存在")
		return
	}
	if readError(w, err) {
		return
	}
	alerts, err := tx.Alert.Query().Where(alert.IncidentIDEQ(id)).All(ctx)
	if readError(w, err) {
		return
	}
	ids := []uuid.UUID{}
	for _, a := range alerts {
		if a.AssetID != nil {
			ids = append(ids, *a.AssetID)
		}
	}
	_, err = tx.Asset.Query().Where(asset.IDIn(ids...)).Order(ent.Asc(asset.FieldID)).Where(func(s *sql.Selector) { s.ForUpdate() }).All(ctx)
	if readError(w, err) {
		return
	}
	visible, err := tx.Incident.Query().Where(incident.IDEQ(id)).Where(incidentScope(groups)...).Exist(ctx)
	if readError(w, err) {
		return
	}
	if !visible {
		Error(w, 404, "not_found", "事件不存在")
		return
	}
	raw, err := json.Marshal(body)
	if readError(w, err) {
		return
	}
	hash := TokenHash(string(raw))
	previous, err := tx.IntegrationIdempotency.Query().Where(integrationidempotency.IntegrationIDEQ(owner.ID), integrationidempotency.MethodEQ(r.Method), integrationidempotency.PathEQ(r.URL.Path), integrationidempotency.KeyEQ(key)).Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		readError(w, err)
		return
	}
	if previous != nil && previous.ExpiresAt.After(time.Now()) {
		if previous.RequestHash != hash {
			Error(w, 409, "idempotency_conflict", "相同幂等键已用于不同请求")
			return
		}
		JSON(w, previous.Status, json.RawMessage(previous.Response))
		return
	}
	if previous != nil {
		if err = tx.IntegrationIdempotency.DeleteOne(previous).Exec(ctx); readError(w, err) {
			return
		}
	}
	result, status, message := apply(tx, row, owner)
	if status >= 400 {
		code := "invalid_argument"
		if status == 409 {
			code = "conflict"
		}
		if status == 403 {
			code = "forbidden"
		}
		if status == 503 {
			code = "unavailable"
		}
		Error(w, status, code, message)
		return
	}
	encoded, err := json.Marshal(result)
	if readError(w, err) {
		return
	}
	err = tx.IntegrationIdempotency.Create().SetIntegrationID(owner.ID).SetMethod(r.Method).SetPath(r.URL.Path).SetKey(key).SetRequestHash(hash).SetStatus(status).SetResponse(encoded).SetExpiresAt(time.Now().Add(7 * 24 * time.Hour)).Exec(ctx)
	if readError(w, err) {
		return
	}
	if err = tx.Commit(); readError(w, err) {
		return
	}
	JSON(w, status, result)
}
func (s *Service) putTicket(w http.ResponseWriter, r *http.Request) {
	var body ticketInput
	if !readWriteBody(w, r, &body) {
		return
	}
	external := r.PathValue("externalId")
	u, err := url.Parse(body.URL)
	if utf8.RuneCountInString(external) < 1 || utf8.RuneCountInString(external) > 200 || strings.ContainsAny(external, "\r\n") || utf8.RuneCountInString(body.Title) > 500 || utf8.RuneCountInString(body.Status) > 100 || len(body.URL) > 2048 || err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		Error(w, 400, "invalid_argument", "工单编号、链接、标题或状态无效")
		return
	}
	s.writeTransaction(w, r, body, "tickets:write", func(tx *ent.Tx, inc *ent.Incident, i *ent.Integration) (any, int, string) {
		existing, err := tx.ExternalTicket.Query().Where(externalticket.IntegrationIDEQ(i.ID), externalticket.ExternalIDEQ(external)).Only(r.Context())
		if err != nil && !ent.IsNotFound(err) {
			return nil, 503, "查询工单失败"
		}
		var ticket *ent.ExternalTicket
		code := 200
		if existing == nil {
			code = 201
			ticket, err = tx.ExternalTicket.Create().SetIntegrationID(i.ID).SetIncidentID(inc.ID).SetExternalID(external).SetURL(body.URL).SetTitle(body.Title).SetStatus(body.Status).Save(r.Context())
		} else {
			if existing.IncidentID != inc.ID {
				return nil, 409, "该工单已关联其他事件"
			}
			ticket, err = tx.ExternalTicket.UpdateOne(existing).SetURL(body.URL).SetTitle(body.Title).SetStatus(body.Status).SetUpdatedAt(time.Now()).Save(r.Context())
		}
		if err != nil {
			return nil, 503, "保存工单失败"
		}
		if err = audit.Checked(r.Context(), tx.AuditLog.Create(), "integration:"+i.ID.String(), audit.RemoteAddr(r), "external_ticket_saved", inc.ID.String(), external); err != nil {
			return nil, 503, "工单审计失败"
		}
		return TicketDTO(ticket), code, ""
	})
}

type resolutionInput struct {
	ExternalID       string `json:"externalId"`
	ExpectedRevision *int64 `json:"expectedRevision"`
	Status           string `json:"status"`
	Note             string `json:"note"`
	Operator         string `json:"operator"`
	ConfirmMalicious bool   `json:"confirmMalicious"`
}

func (s *Service) resolve(w http.ResponseWriter, r *http.Request) {
	var body resolutionInput
	if !readWriteBody(w, r, &body) {
		return
	}
	body.Note = strings.TrimSpace(body.Note)
	if body.ExpectedRevision == nil || *body.ExpectedRevision < 0 || body.ExternalID == "" || utf8.RuneCountInString(body.ExternalID) > 200 || !slices.Contains([]string{"open", "closed", "false_positive"}, body.Status) || utf8.RuneCountInString(body.Note) > 2000 || body.Status != "open" && body.Note == "" || utf8.RuneCountInString(body.Operator) > 200 {
		Error(w, 400, "invalid_argument", "版本、工单编号、状态或处置说明无效")
		return
	}
	s.writeTransaction(w, r, body, "incidents:resolve", func(tx *ent.Tx, inc *ent.Incident, i *ent.Integration) (any, int, string) {
		if !i.ResolutionEnabled || !slices.Contains(i.AllowedResolutions, body.Status) {
			return nil, 403, "此集成未获该状态的回写授权"
		}
		if inc.IntegrationRevision != *body.ExpectedRevision {
			return nil, 409, "事件已变化，请重新读取后确认"
		}
		exists, err := tx.ExternalTicket.Query().Where(externalticket.IntegrationIDEQ(i.ID), externalticket.IncidentIDEQ(inc.ID), externalticket.ExternalIDEQ(body.ExternalID)).Exist(r.Context())
		if err != nil {
			return nil, 503, "查询工单失败"
		}
		if !exists {
			return nil, 409, "必须先关联本集成的工单"
		}
		var verdict struct {
			Verdict string `json:"verdict"`
		}
		_ = json.Unmarshal(inc.AiVerdict, &verdict)
		if body.Status == "false_positive" && verdict.Verdict == "malicious" && (!i.AllowMaliciousFalsePositive || !body.ConfirmMalicious) {
			return nil, 403, "恶意事件按误报关闭需要独立授权与显式确认"
		}
		actor := "integration:" + i.ID.String()
		update := tx.Incident.UpdateOneID(inc.ID).SetStatus(body.Status).ClearClosureProposal()
		if body.Status == "open" {
			update.ClearResolution().ClearResolutionSource().ClearResolvedBy().ClearResolvedAt()
		} else {
			update.SetResolution(body.Note).SetResolutionSource("external_integration").SetResolvedBy(actor).SetResolvedAt(time.Now())
		}
		if err = update.Exec(r.Context()); err != nil {
			return nil, 503, "保存状态失败"
		}
		detail, _ := json.Marshal(map[string]string{"externalId": body.ExternalID, "status": body.Status, "note": body.Note, "claimedOperator": body.Operator})
		if err = audit.Checked(r.Context(), tx.AuditLog.Create(), actor, audit.RemoteAddr(r), "integration_incident_resolved", inc.ID.String(), string(detail)); err != nil {
			return nil, 503, "回写审计失败"
		}
		if err = incidentstate.Record(r.Context(), tx, inc.ID, incidentstate.StatusChanged, incidentstate.Origin{Kind: "integration", ID: i.ID.String()}, inc.Status); err != nil {
			return nil, 503, "保存事件消息失败"
		}
		return map[string]any{"incidentId": inc.ID, "revision": inc.IntegrationRevision + 1, "status": body.Status}, 200, ""
	})
}
