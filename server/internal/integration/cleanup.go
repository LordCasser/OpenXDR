package integration

import (
	"context"
	"encoding/json"
	"time"

	"entgo.io/ent/dialect/sql"
	"openxdr/server/ent"
	"openxdr/server/ent/externalticket"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/integrationattempt"
	"openxdr/server/ent/integrationdelivery"
	"openxdr/server/ent/integrationevent"
	"openxdr/server/ent/integrationidempotency"
	"openxdr/server/internal/audit"
)

const DeliveryRetention = 30 * 24 * time.Hour

// Cleanup 各类清理每轮最多选择 500 条记录，不删除仍被投递引用的消息。
func (w *Worker) Cleanup(ctx context.Context) error {
	tx, err := w.DB.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now()
	cutoff := now.Add(-DeliveryRetention)
	// 事件已清理的在途/待发消息不能再外发；租约完成条件会拒绝旧 worker 的结果。
	missing := tx.IntegrationEvent.Query().Where(integrationevent.KindNEQ("integration.test"), func(s *sql.Selector) {
		deliveries := sql.Table(integrationdelivery.Table)
		s.Where(sql.Exists(sql.Select(deliveries.C(integrationdelivery.FieldID)).From(deliveries).Where(sql.And(sql.ColumnsEQ(deliveries.C(integrationdelivery.FieldEventID), s.C(integrationevent.FieldID)), sql.In(deliveries.C(integrationdelivery.FieldStatus), "pending", "sending")))))
		incidents := sql.Table(incident.Table)
		s.Where(sql.NotExists(sql.Select(incidents.C(incident.FieldID)).From(incidents).Where(sql.ColumnsEQ(incidents.C(incident.FieldID), s.C(integrationevent.FieldIncidentID)))))
	}).Limit(500)
	missingIDs, err := missing.IDs(ctx)
	if err != nil {
		return err
	}
	if err = tx.IntegrationDelivery.Update().Where(integrationdelivery.EventIDIn(missingIDs...), integrationdelivery.StatusIn("pending", "sending")).SetStatus("cancelled_scope").SetLastError("源事件已清理").ClearLeaseUntil().SetCompletedAt(now).Exec(ctx); err != nil {
		return err
	}
	// 暂停期间也遵守重试窗口；保留为失败记录供管理员决定是否重放。
	expired, err := tx.IntegrationDelivery.Query().Where(integrationdelivery.RetryWindowAtLT(now.Add(-24*time.Hour)), integrationdelivery.Or(integrationdelivery.StatusEQ("pending"), integrationdelivery.And(integrationdelivery.StatusEQ("sending"), integrationdelivery.LeaseUntilLTE(now)))).Limit(500).Where(func(s *sql.Selector) { s.ForUpdate(sql.WithLockAction(sql.SkipLocked)) }).IDs(ctx)
	if err != nil {
		return err
	}
	if err = tx.IntegrationDelivery.Update().Where(integrationdelivery.IDIn(expired...)).SetStatus("dead").SetLastError("超过重试窗口，可能已被对方接收").ClearLeaseUntil().SetCompletedAt(now).Exec(ctx); err != nil {
		return err
	}
	terminal, err := tx.IntegrationDelivery.Query().Where(integrationdelivery.StatusIn("delivered", "dead", "cancelled_scope"), integrationdelivery.CompletedAtLT(cutoff)).Order(ent.Asc(integrationdelivery.FieldCompletedAt)).Limit(500).Where(func(s *sql.Selector) { s.ForUpdate(sql.WithLockAction(sql.SkipLocked)) }).All(ctx)
	if err != nil {
		return err
	}
	for _, d := range terminal {
		if _, err = tx.IntegrationAttempt.Delete().Where(integrationattempt.DeliveryIDEQ(d.ID)).Exec(ctx); err != nil {
			return err
		}
		if err = tx.IntegrationDelivery.DeleteOne(d).Exec(ctx); err != nil {
			return err
		}
		detail, _ := json.Marshal(map[string]any{"eventId": d.EventID, "subscriptionId": d.SubscriptionID, "status": d.Status, "attempts": d.Attempts, "completedAt": d.CompletedAt})
		if err = audit.Checked(ctx, tx.AuditLog.Create(), "system", "server", "integration_delivery_retired", d.ID.String(), string(detail)); err != nil {
			return err
		}
	}
	events, err := tx.IntegrationEvent.Query().Where(integrationevent.DispatchedEQ(true), integrationevent.OccurredAtLT(cutoff), func(s *sql.Selector) {
		deliveries := sql.Table(integrationdelivery.Table)
		s.Where(sql.NotExists(sql.Select(deliveries.C(integrationdelivery.FieldID)).From(deliveries).Where(sql.ColumnsEQ(deliveries.C(integrationdelivery.FieldEventID), s.C(integrationevent.FieldID)))))
	}).Limit(500).Where(func(s *sql.Selector) { s.ForUpdate(sql.WithLockAction(sql.SkipLocked)) }).IDs(ctx)
	if err != nil {
		return err
	}
	if _, err = tx.IntegrationEvent.Delete().Where(integrationevent.IDIn(events...)).Exec(ctx); err != nil {
		return err
	}
	orphanTickets, err := tx.ExternalTicket.Query().Where(externalticket.SourceDeletedEQ(false), func(s *sql.Selector) {
		incidents := sql.Table(incident.Table)
		s.Where(sql.NotExists(sql.Select(incidents.C(incident.FieldID)).From(incidents).Where(sql.ColumnsEQ(incidents.C(incident.FieldID), s.C(externalticket.FieldIncidentID)))))
	}).Limit(500).IDs(ctx)
	if err != nil {
		return err
	}
	if err = tx.ExternalTicket.Update().Where(externalticket.IDIn(orphanTickets...)).SetSourceDeleted(true).Exec(ctx); err != nil {
		return err
	}
	keys, err := tx.IntegrationIdempotency.Query().Where(integrationidempotency.ExpiresAtLT(now)).Limit(500).IDs(ctx)
	if err != nil {
		return err
	}
	if _, err = tx.IntegrationIdempotency.Delete().Where(integrationidempotency.IDIn(keys...)).Exec(ctx); err != nil {
		return err
	}
	return tx.Commit()
}
