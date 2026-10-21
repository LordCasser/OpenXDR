//go:build integration

package integration

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
)

func TestIntegrationRetention(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Now()
	old := now.Add(-31 * 24 * time.Hour)
	event := func(dispatched bool, kind string) *ent.IntegrationEvent {
		return db.IntegrationEvent.Create().SetIncidentID(uuid.New()).SetRevision(1).SetKind(kind).SetGroupIds([]string{}).SetPayload(json.RawMessage(`{}`)).SetOccurredAt(old).SetDispatched(dispatched).SaveX(ctx)
	}
	retired := event(true, "integration.test")
	retained := event(true, "integration.test")
	undispatched := event(false, "integration.test")
	missing := event(true, "incident.created")
	create := func(e *ent.IntegrationEvent, state string) *ent.IntegrationDelivery {
		return db.IntegrationDelivery.Create().SetSubscriptionID(uuid.New()).SetEventID(e.ID).SetTargetURL("https://example.test").SetTargetVersion(1).SetSecret([]byte{}).SetKeyID("key").SetStatus(state).SaveX(ctx)
	}
	dead := create(retired, "dead")
	db.IntegrationDelivery.UpdateOne(dead).SetCompletedAt(old).ExecX(ctx)
	db.IntegrationAttempt.Create().SetDeliveryID(dead.ID).SetStartedAt(old).SetEndedAt(old).SetResult("dead").SetLeaseGeneration(1).ExecX(ctx)
	pending := create(retained, "pending")
	cancelled := create(missing, "pending")
	expired := create(retained, "pending")
	db.IntegrationDelivery.UpdateOne(expired).SetRetryWindowAt(now.Add(-25 * time.Hour)).ExecX(ctx)
	db.IntegrationIdempotency.Create().SetIntegrationID(uuid.New()).SetMethod("POST").SetPath("/test").SetKey("key").SetRequestHash("hash").SetStatus(200).SetResponse(json.RawMessage(`{}`)).SetExpiresAt(old).ExecX(ctx)
	ticket := db.ExternalTicket.Create().SetIntegrationID(uuid.New()).SetIncidentID(uuid.New()).SetExternalID("gone").SetURL("https://example.test/ticket").SetStatus("open").SetTitle("test").SaveX(ctx)
	worker := &Worker{DB: db}
	if err := worker.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.IntegrationDelivery.Get(ctx, dead.ID); !ent.IsNotFound(err) {
		t.Fatal("终态记录未清理", err)
	}
	if _, err := db.IntegrationEvent.Get(ctx, retired.ID); !ent.IsNotFound(err) {
		t.Fatal("无引用消息未清理", err)
	}
	if db.IntegrationAttempt.Query().CountX(ctx) != 0 || db.IntegrationIdempotency.Query().CountX(ctx) != 0 || db.AuditLog.Query().CountX(ctx) != 1 {
		t.Fatal("尝试、幂等或审计清理错误")
	}
	if db.IntegrationDelivery.GetX(ctx, pending.ID).Status != "pending" {
		t.Fatal("误删待投递")
	}
	if db.IntegrationDelivery.GetX(ctx, expired.ID).Status != "dead" {
		t.Fatal("超时队列未转为失败")
	}
	if db.IntegrationDelivery.GetX(ctx, cancelled.ID).Status != "cancelled_scope" {
		t.Fatal("源事件清理后仍可发送")
	}
	if !db.ExternalTicket.GetX(ctx, ticket.ID).SourceDeleted {
		t.Fatal("未标记已清理的源事件")
	}
	db.IntegrationEvent.GetX(ctx, retained.ID)
	db.IntegrationEvent.GetX(ctx, undispatched.ID)
}
