//go:build integration

package integration

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent/integrationdelivery"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/hostimport"
	"openxdr/server/internal/incidentstate"
	"openxdr/server/internal/testdb"
)

func TestWebhookDeliveryAndLeaseRecovery(t *testing.T) {
	ctx, db := testdb.New(t)
	owner := db.User.Create().SetUsername("owner").SetPasswordHash("x").SetRole("admin").SaveX(ctx)
	g := db.Group.Create().SetName("ops").SaveX(ctx)
	a := db.Asset.Create().SetHostname("host").SetGroupID(g.ID).SaveX(ctx)
	i := db.Integration.Create().SetName("tickets").SetPurpose("test").SetOwnerID(owner.ID).SetEnabled(true).SetScopes([]string{"incidents:read"}).SaveX(ctx)
	db.IntegrationGroup.Create().SetIntegrationID(i.ID).SetGroupID(g.ID).SaveX(ctx)
	vault, err := hostimport.NewVault(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("v", 32))))
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte(strings.Repeat("s", 32))
	var calls atomic.Int32
	var forcedCode atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if code := forcedCode.Load(); code != 0 {
			w.Header().Set("Retry-After", "120")
			w.Header().Set("Location", "/redirected")
			w.WriteHeader(int(code))
			return
		}
		body, _ := io.ReadAll(r.Body)
		expected := SignEvent(secret, r.Header.Get("X-OpenXDR-Timestamp"), r.Header.Get("X-OpenXDR-Event-ID"), body)
		if r.Header.Get("X-OpenXDR-Signature") != expected {
			t.Error("签名校验失败")
			w.WriteHeader(401)
			return
		}
		if calls.Load() == 1 {
			w.WriteHeader(503)
		} else {
			w.WriteHeader(204)
		}
	}))
	defer server.Close()
	subID := uuid.New()
	sealed, err := vault.Seal(hostimport.Secret{Password: base64.StdEncoding.EncodeToString(secret)}, "integration-subscription:"+subID.String())
	if err != nil {
		t.Fatal(err)
	}
	sub := db.IntegrationSubscription.Create().SetID(subID).SetIntegrationID(i.ID).SetName("ticket").SetURL(server.URL).SetEnabled(true).SetGroupIds([]string{g.ID.String()}).SetKinds([]string{incidentstate.Created}).SetPeriods([]schema.SubscriptionPeriod{{From: time.Now().Add(-time.Minute)}}).SetSecret(sealed).SetKeyID("key1").SaveX(ctx)
	tx, err := db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	inc := tx.Incident.Create().SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	ev := tx.Event.Create().SetTs(time.Now()).SetClassUID(1007).SetSource("agent").SetAssetID(a.ID).SetRaw(json.RawMessage(`{}`)).SaveX(ctx)
	tx.Alert.Create().SetTs(time.Now()).SetSeverity(3).SetRuleID("r").SetEventID(ev.ID).SetAssetID(a.ID).SetIncidentID(inc.ID).SaveX(ctx)
	if err = incidentstate.Record(ctx, tx, inc.ID, incidentstate.Created, incidentstate.Origin{Kind: "system"}, ""); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	worker := &Worker{DB: db, Vault: vault, transport: func() *http.Transport { return server.Client().Transport.(*http.Transport).Clone() }}
	if err = worker.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	d := db.IntegrationDelivery.Query().OnlyX(ctx)
	if calls.Load() != 1 || d.Status != "pending" || d.Attempts != 1 || db.IntegrationAttempt.Query().CountX(ctx) != 1 {
		t.Fatal("失败未正确记录", d)
	}
	db.IntegrationDelivery.UpdateOne(d).SetNextAt(time.Now().Add(-time.Minute)).ExecX(ctx)
	if err = worker.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	d = db.IntegrationDelivery.GetX(ctx, d.ID)
	if d.Status != "delivered" || d.Attempts != 2 || calls.Load() != 2 {
		t.Fatal("重试未成功", d)
	}
	// 模拟工作进程在 HTTP 前失联，旧租约完成结果不能覆盖新一代。
	db.IntegrationDelivery.UpdateOne(d).SetStatus("pending").SetNextAt(time.Now().Add(-time.Minute)).ExecX(ctx)
	first, err := worker.claim(ctx)
	if err != nil || first == nil {
		t.Fatal(err)
	}
	db.IntegrationDelivery.UpdateOneID(d.ID).SetLeaseUntil(time.Now().Add(-time.Minute)).ExecX(ctx)
	second, err := worker.claim(ctx)
	if err != nil || second == nil || second.LeaseGeneration <= first.LeaseGeneration {
		t.Fatal("租约未恢复", err)
	}
	if err = worker.finish(ctx, first, time.Now(), 200, "delivered", "", 0); err != nil {
		t.Fatal(err)
	}
	if db.IntegrationDelivery.GetX(ctx, d.ID).Status != "sending" {
		t.Fatal("过期工作进程覆盖结果")
	}
	db.Asset.UpdateOne(a).ClearGroupID().ExecX(ctx)
	if err = worker.deliver(ctx, second); err != nil {
		t.Fatal(err)
	}
	if db.IntegrationDelivery.GetX(ctx, d.ID).Status != "cancelled_scope" || calls.Load() != 2 {
		t.Fatal("移组后仍发送旧消息")
	}
	if db.IntegrationDelivery.Query().Where(integrationdelivery.SubscriptionIDEQ(sub.ID)).CountX(ctx) != 1 {
		t.Fatal("重复分发")
	}
	db.Asset.UpdateOne(a).SetGroupID(g.ID).ExecX(ctx)
	for _, tc := range []struct {
		name           string
		code, attempts int
		age            time.Duration
		want           string
		requests       int32
	}{
		{"redirect", 302, 0, 0, "dead", 1},
		{"permanent", 400, 0, 0, "dead", 1},
		{"timeout", 408, 0, 0, "pending", 1},
		{"rate-limit", 429, 0, 0, "pending", 1},
		{"attempt-limit", 503, 19, 0, "dead", 1},
		{"expired", 200, 0, 25 * time.Hour, "dead", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forcedCode.Store(int32(tc.code))
			before := calls.Load()
			db.IntegrationDelivery.UpdateOneID(d.ID).SetStatus("pending").SetAttempts(tc.attempts).SetRetryWindowAt(time.Now().Add(-tc.age)).SetNextAt(time.Now().Add(-time.Minute)).ClearCompletedAt().ExecX(ctx)
			if err := worker.Tick(ctx); err != nil {
				t.Fatal(err)
			}
			got := db.IntegrationDelivery.GetX(ctx, d.ID)
			if got.Status != tc.want || calls.Load()-before != tc.requests {
				t.Fatalf("状态/请求次数不符: %s/%d", got.Status, calls.Load()-before)
			}
			if tc.code == 429 && time.Until(got.NextAt) < 119*time.Second {
				t.Fatal("未遵守 Retry-After")
			}
		})
	}
}
