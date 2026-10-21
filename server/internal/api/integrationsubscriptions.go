package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/integrationattempt"
	"openxdr/server/ent/integrationdelivery"
	"openxdr/server/ent/integrationgroup"
	"openxdr/server/ent/integrationsubscription"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/hostimport"
	"openxdr/server/internal/incidentstate"
	integrationapi "openxdr/server/internal/integration"
)

type subscriptionInput struct {
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	GroupIDs    []string `json:"groupIds"`
	Kinds       []string `json:"kinds"`
	Enabled     bool     `json:"enabled"`
	MovePending bool     `json:"movePending"`
}
type subscriptionRow struct {
	ID       uuid.UUID `json:"id"`
	Name     string    `json:"name"`
	URL      string    `json:"url"`
	GroupIDs []string  `json:"groupIds"`
	Kinds    []string  `json:"kinds"`
	Enabled  bool      `json:"enabled"`
	Version  int64     `json:"version"`
	KeyID    string    `json:"keyId"`
	Secret   string    `json:"secret,omitempty"`
}

func subscriptionDTO(s *ent.IntegrationSubscription) subscriptionRow {
	return subscriptionRow{s.ID, s.Name, s.URL, s.GroupIds, s.Kinds, s.Enabled, s.Version, s.KeyID, ""}
}
func subscriptionConfig(s *ent.IntegrationSubscription, at time.Time) schema.SubscriptionConfig {
	return schema.SubscriptionConfig{From: at, URL: s.URL, Version: s.Version, GroupIDs: s.GroupIds, Kinds: s.Kinds, Secret: s.Secret, KeyID: s.KeyID}
}
func issueWebhookSecret(vault *hostimport.Vault, id uuid.UUID) (string, []byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	defer clear(raw)
	plain := base64.StdEncoding.EncodeToString(raw)
	sealed, err := vault.Seal(hostimport.Secret{Password: plain}, "integration-subscription:"+id.String())
	return plain, sealed, err
}
func subscriptionByPath(tx *ent.Tx, w http.ResponseWriter, r *http.Request) (*ent.IntegrationSubscription, bool) {
	id, ok := integrationID(w, r)
	if !ok {
		return nil, false
	}
	sid, err := uuid.Parse(r.PathValue("subscriptionId"))
	if err != nil {
		integrationapi.Error(w, 404, "not_found", "订阅不存在")
		return nil, false
	}
	row, err := tx.IntegrationSubscription.Query().Where(integrationsubscription.IDEQ(sid), integrationsubscription.IntegrationIDEQ(id), integrationsubscription.DeletedEQ(false)).Where(func(s *sql.Selector) { s.ForUpdate() }).Only(r.Context())
	return row, !integrationFailure(w, err)
}
func finishSubscription(w http.ResponseWriter, r *http.Request, tx *ent.Tx, action, target string, result any) bool {
	if integrationFailure(w, audit.Checked(r.Context(), tx.AuditLog.Create(), audit.Actor(r.Context()), audit.RemoteAddr(r), action, target, "")) {
		return false
	}
	if integrationFailure(w, tx.Commit()) {
		return false
	}
	integrationapi.JSON(w, 200, result)
	return true
}
func mapIntegrationSubscriptions(mux *http.ServeMux, db *ent.Client, vault *hostimport.Vault) {
	base := "/api/system-integrations/{id}/subscriptions"
	mux.HandleFunc("GET "+base, func(w http.ResponseWriter, r *http.Request) {
		id, ok := integrationID(w, r)
		if !ok {
			return
		}
		rows, err := db.IntegrationSubscription.Query().Where(integrationsubscription.IntegrationIDEQ(id), integrationsubscription.DeletedEQ(false)).Order(ent.Asc(integrationsubscription.FieldCreatedAt)).All(r.Context())
		if integrationFailure(w, err) {
			return
		}
		out := make([]subscriptionRow, 0, len(rows))
		for _, s := range rows {
			out = append(out, subscriptionDTO(s))
		}
		integrationapi.JSON(w, 200, out)
	})
	save := func(w http.ResponseWriter, r *http.Request) {
		id, ok := integrationID(w, r)
		if !ok {
			return
		}
		var body subscriptionInput
		if !integrationDecode(w, r, &body) {
			return
		}
		body.Name = strings.TrimSpace(body.Name)
		if body.Name == "" || utf8.RuneCountInString(body.Name) > 100 || len(body.GroupIDs) == 0 || len(body.GroupIDs) > 1000 || len(body.Kinds) == 0 || len(body.Kinds) > 4 {
			integrationapi.Error(w, 400, "invalid_argument", "名称、组或事件类型无效")
			return
		}
		if _, err := integrationapi.ValidateTarget(body.URL); err != nil {
			integrationapi.Error(w, 400, "invalid_argument", err.Error())
			return
		}
		for _, kind := range body.Kinds {
			if !slices.Contains([]string{incidentstate.Created, incidentstate.Triaged, incidentstate.EvidenceUpdated, incidentstate.StatusChanged}, kind) {
				integrationapi.Error(w, 400, "invalid_argument", "事件类型无效")
				return
			}
		}
		tx, err := db.Tx(r.Context())
		if integrationFailure(w, err) {
			return
		}
		defer tx.Rollback()
		owner, err := tx.Integration.Get(r.Context(), id)
		if integrationFailure(w, err) {
			return
		}
		if !slices.Contains(owner.Scopes, "incidents:read") {
			integrationapi.Error(w, 400, "invalid_argument", "订阅需要 incidents:read 授权")
			return
		}
		grants, err := tx.IntegrationGroup.Query().Where(integrationgroup.IntegrationIDEQ(id)).All(r.Context())
		if integrationFailure(w, err) {
			return
		}
		allowed := []string{}
		for _, g := range grants {
			allowed = append(allowed, g.GroupID.String())
		}
		for _, g := range body.GroupIDs {
			if !slices.Contains(allowed, g) {
				integrationapi.Error(w, 400, "invalid_argument", "订阅组超出集成授权")
				return
			}
		}
		slices.Sort(body.GroupIDs)
		body.GroupIDs = slices.Compact(body.GroupIDs)
		slices.Sort(body.Kinds)
		body.Kinds = slices.Compact(body.Kinds)
		now := time.Now().UTC()
		var row *ent.IntegrationSubscription
		var plain string
		if r.Method == http.MethodPost {
			sid := uuid.New()
			var sealed []byte
			plain, sealed, err = issueWebhookSecret(vault, sid)
			if integrationFailure(w, err) {
				return
			}
			periods := []schema.SubscriptionPeriod{}
			if body.Enabled {
				periods = append(periods, schema.SubscriptionPeriod{From: now})
			}
			row, err = tx.IntegrationSubscription.Create().SetID(sid).SetIntegrationID(id).SetName(body.Name).SetURL(body.URL).SetGroupIds(body.GroupIDs).SetKinds(body.Kinds).SetEnabled(body.Enabled).SetPeriods(periods).SetSecret(sealed).SetKeyID(uuid.NewString()).Save(r.Context())
			if integrationFailure(w, err) {
				return
			}
			row, err = tx.IntegrationSubscription.UpdateOne(row).SetConfigurations([]schema.SubscriptionConfig{subscriptionConfig(row, now)}).Save(r.Context())
		} else {
			var ok bool
			row, ok = subscriptionByPath(tx, w, r)
			if !ok {
				return
			}
			periods := row.Periods
			if row.Enabled && !body.Enabled && len(periods) > 0 {
				periods[len(periods)-1].To = &now
			}
			if !row.Enabled && body.Enabled {
				periods = append(periods, schema.SubscriptionPeriod{From: now})
			}
			configs := row.Configurations
			if len(configs) == 0 {
				configs = []schema.SubscriptionConfig{subscriptionConfig(row, row.CreatedAt)}
			}
			configs[len(configs)-1].To = &now
			row, err = tx.IntegrationSubscription.UpdateOne(row).SetName(body.Name).SetURL(body.URL).SetGroupIds(body.GroupIDs).SetKinds(body.Kinds).SetEnabled(body.Enabled).SetPeriods(periods).AddVersion(1).Save(r.Context())
			if integrationFailure(w, err) {
				return
			}
			configs = append(configs, subscriptionConfig(row, now))
			if body.MovePending {
				for n := range configs {
					configs[n].URL = row.URL
					configs[n].Version = row.Version
				}
				err = tx.IntegrationDelivery.Update().Where(integrationdelivery.SubscriptionIDEQ(row.ID), integrationdelivery.StatusIn("pending", "dead")).SetTargetURL(row.URL).SetTargetVersion(row.Version).Exec(r.Context())
				if integrationFailure(w, err) {
					return
				}
			}
			row, err = tx.IntegrationSubscription.UpdateOne(row).SetConfigurations(configs).Save(r.Context())
		}
		if integrationFailure(w, err) {
			return
		}
		out := subscriptionDTO(row)
		out.Secret = plain
		finishSubscription(w, r, tx, "integration_subscription_saved", row.ID.String(), out)
	}
	mux.HandleFunc("POST "+base, save)
	mux.HandleFunc("PUT "+base+"/{subscriptionId}", save)
	mux.HandleFunc("DELETE "+base+"/{subscriptionId}", func(w http.ResponseWriter, r *http.Request) {
		tx, err := db.Tx(r.Context())
		if integrationFailure(w, err) {
			return
		}
		defer tx.Rollback()
		row, ok := subscriptionByPath(tx, w, r)
		if !ok {
			return
		}
		now := time.Now()
		periods := row.Periods
		if row.Enabled && len(periods) > 0 {
			periods[len(periods)-1].To = &now
		}
		err = tx.IntegrationSubscription.UpdateOne(row).SetEnabled(false).SetDeleted(true).SetPeriods(periods).Exec(r.Context())
		if integrationFailure(w, err) {
			return
		}
		err = tx.IntegrationDelivery.Update().Where(integrationdelivery.SubscriptionIDEQ(row.ID), integrationdelivery.StatusIn("pending", "sending")).SetStatus("cancelled_scope").ClearLeaseUntil().SetCompletedAt(now).SetLastError("订阅已删除").Exec(r.Context())
		if integrationFailure(w, err) {
			return
		}
		finishSubscription(w, r, tx, "integration_subscription_deleted", row.ID.String(), map[string]bool{"deleted": true})
	})
	mux.HandleFunc("POST "+base+"/{subscriptionId}/rotate", func(w http.ResponseWriter, r *http.Request) {
		tx, err := db.Tx(r.Context())
		if integrationFailure(w, err) {
			return
		}
		defer tx.Rollback()
		row, ok := subscriptionByPath(tx, w, r)
		if !ok {
			return
		}
		if row.Enabled {
			integrationapi.Error(w, 409, "conflict", "先暂停订阅，配置新密钥后再恢复")
			return
		}
		active, err := tx.IntegrationDelivery.Query().Where(integrationdelivery.SubscriptionIDEQ(row.ID), integrationdelivery.StatusEQ("sending"), integrationdelivery.LeaseUntilGT(time.Now())).Exist(r.Context())
		if integrationFailure(w, err) {
			return
		}
		if active {
			integrationapi.Error(w, 409, "conflict", "尚有在途投递，请等待租约结束后轮换")
			return
		}
		if err = tx.IntegrationDelivery.Update().Where(integrationdelivery.SubscriptionIDEQ(row.ID), integrationdelivery.StatusEQ("sending")).SetStatus("pending").ClearLeaseUntil().SetNextAt(time.Now()).Exec(r.Context()); integrationFailure(w, err) {
			return
		}
		plain, sealed, err := issueWebhookSecret(vault, row.ID)
		if integrationFailure(w, err) {
			return
		}
		keyID := uuid.NewString()
		configs := row.Configurations
		for n := range configs {
			configs[n].Secret = sealed
			configs[n].KeyID = keyID
		}
		row, err = tx.IntegrationSubscription.UpdateOne(row).SetSecret(sealed).SetKeyID(keyID).SetConfigurations(configs).Save(r.Context())
		if integrationFailure(w, err) {
			return
		}
		err = tx.IntegrationDelivery.Update().Where(integrationdelivery.SubscriptionIDEQ(row.ID), integrationdelivery.StatusIn("pending", "dead")).SetSecret(sealed).SetKeyID(keyID).Exec(r.Context())
		if integrationFailure(w, err) {
			return
		}
		out := subscriptionDTO(row)
		out.Secret = plain
		finishSubscription(w, r, tx, "integration_subscription_key_rotated", row.ID.String(), out)
	})
	mux.HandleFunc("POST "+base+"/{subscriptionId}/test", func(w http.ResponseWriter, r *http.Request) {
		tx, err := db.Tx(r.Context())
		if integrationFailure(w, err) {
			return
		}
		defer tx.Rollback()
		row, ok := subscriptionByPath(tx, w, r)
		if !ok {
			return
		}
		if !row.Enabled {
			integrationapi.Error(w, 409, "conflict", "先启用订阅再测试")
			return
		}
		id := uuid.New()
		now := time.Now().UTC()
		payload, _ := json.Marshal(map[string]any{"schemaVersion": "1", "eventId": id, "type": "integration.test", "occurredAt": now, "data": map[string]string{"message": "OpenXDR 集成测试"}})
		err = tx.IntegrationEvent.Create().SetID(id).SetIncidentID(id).SetRevision(0).SetKind("integration.test").SetOccurredAt(now).SetGroupIds(row.GroupIds).SetPayload(payload).SetDispatched(true).Exec(r.Context())
		if integrationFailure(w, err) {
			return
		}
		delivery, err := tx.IntegrationDelivery.Create().SetSubscriptionID(row.ID).SetEventID(id).SetTargetURL(row.URL).SetTargetVersion(row.Version).SetSecret(row.Secret).SetKeyID(row.KeyID).Save(r.Context())
		if integrationFailure(w, err) {
			return
		}
		finishSubscription(w, r, tx, "integration_subscription_test", row.ID.String(), map[string]any{"deliveryId": delivery.ID, "eventId": id})
	})
	mapIntegrationDeliveries(mux, db)
}

type deliveryRow struct {
	ID             uuid.UUID  `json:"id"`
	SubscriptionID uuid.UUID  `json:"subscriptionId"`
	EventID        uuid.UUID  `json:"eventId"`
	Status         string     `json:"status"`
	Attempts       int        `json:"attempts"`
	CreatedAt      time.Time  `json:"createdAt"`
	NextAt         time.Time  `json:"nextAt"`
	LastError      string     `json:"lastError"`
	TargetURL      string     `json:"targetUrl"`
	TargetVersion  int64      `json:"targetVersion"`
	CompletedAt    *time.Time `json:"completedAt"`
}

func mapIntegrationDeliveries(mux *http.ServeMux, db *ent.Client) {
	mux.HandleFunc("GET /api/system-integrations/{id}/deliveries", func(w http.ResponseWriter, r *http.Request) {
		id, ok := integrationID(w, r)
		if !ok {
			return
		}
		subs, err := db.IntegrationSubscription.Query().Where(integrationsubscription.IntegrationIDEQ(id)).IDs(r.Context())
		if integrationFailure(w, err) {
			return
		}
		q := db.IntegrationDelivery.Query().Where(integrationdelivery.SubscriptionIDIn(subs...))
		values := r.URL.Query()
		for key, items := range values {
			if len(items) != 1 || !slices.Contains([]string{"status", "subscriptionId", "from", "to", "limit", "offset"}, key) {
				integrationapi.Error(w, 400, "invalid_argument", "未知或重复筛选参数")
				return
			}
		}
		if state := values.Get("status"); state != "" {
			if !slices.Contains([]string{"pending", "sending", "delivered", "dead", "cancelled_scope"}, state) {
				integrationapi.Error(w, 400, "invalid_argument", "投递状态无效")
				return
			}
			q.Where(integrationdelivery.StatusEQ(state))
		}
		if value := values.Get("subscriptionId"); value != "" {
			sid, err := uuid.Parse(value)
			if err != nil {
				integrationapi.Error(w, 400, "invalid_argument", "订阅 ID 无效")
				return
			}
			q.Where(integrationdelivery.SubscriptionIDEQ(sid))
		}
		var from, to *time.Time
		for key, target := range map[string]**time.Time{"from": &from, "to": &to} {
			if value := values.Get(key); value != "" {
				at, err := time.Parse(time.RFC3339Nano, value)
				if err != nil {
					integrationapi.Error(w, 400, "invalid_argument", "时间范围无效")
					return
				}
				*target = &at
			}
		}
		if from != nil && to != nil && !from.Before(*to) {
			integrationapi.Error(w, 400, "invalid_argument", "结束时间必须晚于开始时间")
			return
		}
		if from != nil {
			q.Where(integrationdelivery.CreatedAtGTE(*from))
		}
		if to != nil {
			q.Where(integrationdelivery.CreatedAtLT(*to))
		}
		limit, offset := 50, 0
		for key, target := range map[string]*int{"limit": &limit, "offset": &offset} {
			if value := values.Get(key); value != "" {
				n, err := strconv.Atoi(value)
				if err != nil {
					integrationapi.Error(w, 400, "invalid_argument", "分页参数无效")
					return
				}
				*target = n
			}
		}
		if limit < 1 || limit > 200 || offset < 0 || offset > 100000 {
			integrationapi.Error(w, 400, "invalid_argument", "分页范围无效")
			return
		}
		total, err := q.Clone().Count(r.Context())
		if integrationFailure(w, err) {
			return
		}
		rows, err := q.Order(ent.Desc(integrationdelivery.FieldCreatedAt), ent.Desc(integrationdelivery.FieldID)).Offset(offset).Limit(limit).All(r.Context())
		if integrationFailure(w, err) {
			return
		}
		var counts []struct {
			Status string `json:"status"`
			Count  int    `json:"count"`
		}
		err = db.IntegrationDelivery.Query().Where(integrationdelivery.SubscriptionIDIn(subs...)).GroupBy(integrationdelivery.FieldStatus).Aggregate(ent.Count()).Scan(r.Context(), &counts)
		if integrationFailure(w, err) {
			return
		}
		states := map[string]int{}
		for _, c := range counts {
			states[c.Status] = c.Count
		}
		oldest, err := db.IntegrationDelivery.Query().Where(integrationdelivery.SubscriptionIDIn(subs...), integrationdelivery.StatusIn("pending", "sending")).Order(ent.Asc(integrationdelivery.FieldCreatedAt)).First(r.Context())
		if err != nil && !ent.IsNotFound(err) {
			integrationFailure(w, err)
			return
		}
		var oldestAt *time.Time
		if oldest != nil {
			oldestAt = &oldest.CreatedAt
		}

		out := make([]deliveryRow, 0, len(rows))
		for _, d := range rows {
			out = append(out, deliveryRow{d.ID, d.SubscriptionID, d.EventID, d.Status, d.Attempts, d.CreatedAt, d.NextAt, d.LastError, d.TargetURL, d.TargetVersion, d.CompletedAt})
		}
		integrationapi.JSON(w, 200, map[string]any{"items": out, "total": total, "limit": limit, "offset": offset, "truncated": offset+len(rows) < total, "summary": map[string]any{"counts": states, "oldestPendingAt": oldestAt}})
	})
	mux.HandleFunc("GET /api/system-integrations/{id}/deliveries/{deliveryId}/attempts", func(w http.ResponseWriter, r *http.Request) {
		id, ok := integrationID(w, r)
		if !ok {
			return
		}
		did, err := uuid.Parse(r.PathValue("deliveryId"))
		if err != nil {
			integrationapi.Error(w, 404, "not_found", "投递不存在")
			return
		}
		d, err := db.IntegrationDelivery.Get(r.Context(), did)
		if integrationFailure(w, err) {
			return
		}
		sub, err := db.IntegrationSubscription.Get(r.Context(), d.SubscriptionID)
		if integrationFailure(w, err) {
			return
		}
		if sub.IntegrationID != id {
			integrationapi.Error(w, 404, "not_found", "投递不存在")
			return
		}
		rows, err := db.IntegrationAttempt.Query().Where(integrationattempt.DeliveryIDEQ(did)).Order(ent.Desc(integrationattempt.FieldStartedAt)).Limit(100).All(r.Context())
		if integrationFailure(w, err) {
			return
		}
		out := make([]map[string]any, 0, len(rows))
		for _, a := range rows {
			out = append(out, map[string]any{"startedAt": a.StartedAt, "endedAt": a.EndedAt, "httpStatus": a.HTTPStatus, "result": a.Result, "leaseGeneration": a.LeaseGeneration})
		}
		integrationapi.JSON(w, 200, out)
	})
	mux.HandleFunc("POST /api/system-integrations/{id}/deliveries/{deliveryId}/retry", func(w http.ResponseWriter, r *http.Request) {
		id, ok := integrationID(w, r)
		if !ok {
			return
		}
		did, err := uuid.Parse(r.PathValue("deliveryId"))
		if err != nil {
			integrationapi.Error(w, 404, "not_found", "投递不存在")
			return
		}
		tx, err := db.Tx(r.Context())
		if integrationFailure(w, err) {
			return
		}
		defer tx.Rollback()
		d, err := tx.IntegrationDelivery.Query().Where(integrationdelivery.IDEQ(did)).Where(func(s *sql.Selector) { s.ForUpdate() }).Only(r.Context())
		if integrationFailure(w, err) {
			return
		}
		sub, err := tx.IntegrationSubscription.Get(r.Context(), d.SubscriptionID)
		if integrationFailure(w, err) {
			return
		}
		if sub.IntegrationID != id || sub.Deleted {
			integrationapi.Error(w, 404, "not_found", "投递不存在")
			return
		}
		if d.Status != "dead" {
			integrationapi.Error(w, 409, "conflict", "只允许重放失败投递")
			return
		}
		if _, err = tx.IntegrationEvent.Get(r.Context(), d.EventID); err != nil {
			integrationapi.Error(w, 409, "conflict", "原消息已清理，不能重放")
			return
		}
		err = tx.IntegrationDelivery.UpdateOne(d).SetStatus("pending").SetAttempts(0).SetRetryWindowAt(time.Now()).SetNextAt(time.Now()).ClearCompletedAt().SetLastError("").Exec(r.Context())
		if integrationFailure(w, err) {
			return
		}
		finishSubscription(w, r, tx, "integration_delivery_replayed", d.ID.String(), map[string]any{"eventId": d.EventID, "status": "pending"})
	})
}
