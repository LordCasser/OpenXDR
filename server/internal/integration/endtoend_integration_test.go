//go:build integration

package integration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/hostimport"
	"openxdr/server/internal/incidentstate"
	"openxdr/server/internal/testdb"
)

// 受控工单适配器：验签、持久去重语义、API 关联、状态回写；首次响应丢失后重复接收不再执行。
func TestIncidentWebhookTicketRoundTrip(t *testing.T) {
	ctx, db := testdb.New(t)
	owner := db.User.Create().SetUsername("owner").SetPasswordHash("x").SetRole("admin").SaveX(ctx)
	g := db.Group.Create().SetName("ops").SaveX(ctx)
	asset := db.Asset.Create().SetHostname("host").SetGroupID(g.ID).SaveX(ctx)
	i := db.Integration.Create().SetName("ticket-system").SetPurpose("test").SetOwnerID(owner.ID).SetEnabled(true).SetScopes(AllowedScopes).SetResolutionEnabled(true).SetAllowedResolutions([]string{"closed"}).SaveX(ctx)
	db.IntegrationGroup.Create().SetIntegrationID(i.ID).SetGroupID(g.ID).SaveX(ctx)
	plain := "oxi_" + strings.Repeat("t", 43)
	db.IntegrationToken.Create().SetIntegrationID(i.ID).SetPrefix("oxi_ttt").SetTokenHash(TokenHash(plain)).SetScopes(AllowedScopes).SetExpiresAt(time.Now().Add(time.Hour)).SaveX(ctx)
	service := &Service{DB: db, Enabled: true, CursorKey: []byte(strings.Repeat("c", 32))}
	api := service.Handler()
	secret := []byte(strings.Repeat("s", 32))
	var received atomic.Int32
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		if r.Header.Get("X-OpenXDR-Signature") != SignEvent(secret, r.Header.Get("X-OpenXDR-Timestamp"), r.Header.Get("X-OpenXDR-Event-ID"), body) {
			t.Error("签名错误")
			w.WriteHeader(401)
			return
		}
		var event incidentstate.Event
		if err = json.Unmarshal(body, &event); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		// 外部平台以事件 ID 作为请求幂等键，重送仍调用 API，用平台持久幂等记录验证防重复。
		base := "/api/integration/v1/incidents/" + event.IncidentID.String()
		requests := []struct {
			method, path, key string
			body              any
		}{
			{"PUT", base + "/tickets/SEC-001", event.EventID.String() + "-link", ticketInput{URL: "https://desk.example.test/SEC-001", Status: "resolved", Title: "受控验证工单"}},
			{"POST", base + "/resolution", event.EventID.String() + "-resolve", resolutionInput{ExternalID: "SEC-001", ExpectedRevision: &event.Revision, Status: "closed", Note: "已修复并复核", Operator: "external-operator"}},
		}
		for _, request := range requests {
			raw, _ := json.Marshal(request.body)
			req := httptest.NewRequest(request.method, request.path, bytes.NewReader(raw))
			req.Header.Set("Authorization", "Bearer "+plain)
			req.Header.Set("Idempotency-Key", request.key)
			result := httptest.NewRecorder()
			api.ServeHTTP(result, req)
			if result.Code >= 300 {
				t.Errorf("回写失败 %d %s", result.Code, result.Body.String())
				w.WriteHeader(500)
				return
			}
		}
		if received.Add(1) == 1 {
			w.WriteHeader(503)
		} else {
			w.WriteHeader(204)
		}
	}))
	defer receiver.Close()
	vault, err := hostimport.NewVault(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("v", 32))))
	if err != nil {
		t.Fatal(err)
	}
	sid := uuid.New()
	sealed, err := vault.Seal(hostimport.Secret{Password: base64.StdEncoding.EncodeToString(secret)}, "integration-subscription:"+sid.String())
	if err != nil {
		t.Fatal(err)
	}
	db.IntegrationSubscription.Create().SetID(sid).SetIntegrationID(i.ID).SetName("desk").SetURL(receiver.URL).SetEnabled(true).SetGroupIds([]string{g.ID.String()}).SetKinds([]string{incidentstate.Created}).SetPeriods([]schema.SubscriptionPeriod{{From: time.Now().Add(-time.Minute)}}).SetSecret(sealed).SetKeyID("key1").ExecX(ctx)
	tx, err := db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	inc := tx.Incident.Create().SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	event := tx.Event.Create().SetTs(time.Now()).SetClassUID(1007).SetSource("agent").SetAssetID(asset.ID).SetRaw(json.RawMessage(`{}`)).SaveX(ctx)
	tx.Alert.Create().SetTs(time.Now()).SetSeverity(4).SetRuleID("test").SetEventID(event.ID).SetAssetID(asset.ID).SetIncidentID(inc.ID).ExecX(ctx)
	if err = incidentstate.Record(ctx, tx, inc.ID, incidentstate.Created, incidentstate.Origin{Kind: "system"}, ""); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	worker := &Worker{DB: db, Vault: vault, transport: func() *http.Transport { return receiver.Client().Transport.(*http.Transport).Clone() }}
	if err = worker.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	delivery := db.IntegrationDelivery.Query().OnlyX(ctx)
	if delivery.Status != "pending" {
		t.Fatal("应在远端已处理后重试", delivery.Status)
	}
	db.IntegrationDelivery.UpdateOne(delivery).SetNextAt(time.Now().Add(-time.Minute)).ExecX(ctx)
	if err = worker.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	result := db.Incident.GetX(ctx, inc.ID)
	if result.Status != "closed" || result.IntegrationRevision != 2 || db.ExternalTicket.Query().CountX(ctx) != 1 || db.IntegrationIdempotency.Query().CountX(ctx) != 2 || db.IntegrationEvent.Query().CountX(ctx) != 2 || received.Load() != 2 {
		t.Fatal("链路或去重未完成", fmt.Sprint(result.Status, result.IntegrationRevision, received.Load()))
	}
	if db.IntegrationDelivery.GetX(ctx, delivery.ID).Status != "delivered" || db.AuditLog.Query().CountX(ctx) != 2 {
		t.Fatal("投递结果或审计错误")
	}
}
