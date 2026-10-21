package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/group"
	"openxdr/server/ent/incident"
	entintegration "openxdr/server/ent/integration"
	"openxdr/server/ent/integrationdelivery"
	"openxdr/server/ent/integrationevent"
	"openxdr/server/ent/integrationgroup"
	"openxdr/server/ent/integrationsubscription"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/hostimport"
)

type Worker struct {
	DB     *ent.Client
	Vault  *hostimport.Vault
	Policy OutboundPolicy
	// 测试在包内注入接收器，生产始终使用校验 DNS 与证书的 transport。
	transport func() *http.Transport
}

func (w *Worker) Run(ctx context.Context) { w.run(ctx, true) }

// RunMaintenance 关闭出站时仍分发本地记录并清理过期数据，不发 HTTP 请求。
func (w *Worker) RunMaintenance(ctx context.Context) { w.run(ctx, false) }
func (w *Worker) run(ctx context.Context, send bool) {
	nextCleanup := time.Time{}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		var err error
		if send {
			err = w.Tick(ctx)
		} else {
			err = w.dispatch(ctx)
		}
		if err != nil {
			slog.Error("集成投递周期失败", "err", err)
		}
		if time.Now().After(nextCleanup) {
			if err = w.Cleanup(ctx); err != nil {
				slog.Error("集成记录清理失败", "err", err)
			}
			nextCleanup = time.Now().Add(time.Minute)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (w *Worker) Tick(ctx context.Context) error {
	if err := w.dispatch(ctx); err != nil {
		return err
	}
	for range 20 {
		d, err := w.claim(ctx)
		if err != nil {
			return err
		}
		if d == nil {
			break
		}
		if err = w.deliver(ctx, d); err != nil {
			return fmt.Errorf("deliveryId=%s eventId=%s: %w", d.ID, d.EventID, err)
		}
	}
	return nil
}
func activeAt(s *ent.IntegrationSubscription, at time.Time) bool {
	for _, p := range s.Periods {
		if !at.Before(p.From) && (p.To == nil || at.Before(*p.To)) {
			return true
		}
	}
	return false
}
func covers(allowed, required []string) bool {
	if len(required) == 0 {
		return false
	}
	for _, g := range required {
		if g == uuid.Nil.String() || !slices.Contains(allowed, g) {
			return false
		}
	}
	return true
}
func configAt(s *ent.IntegrationSubscription, at time.Time) (schema.SubscriptionConfig, bool) {
	if len(s.Configurations) == 0 {
		return schema.SubscriptionConfig{URL: s.URL, Version: s.Version, GroupIDs: s.GroupIds, Kinds: s.Kinds, Secret: s.Secret, KeyID: s.KeyID}, true
	}
	for _, c := range s.Configurations {
		if !at.Before(c.From) && (c.To == nil || at.Before(*c.To)) {
			return c, true
		}
	}
	return schema.SubscriptionConfig{}, false
}
func (w *Worker) dispatch(ctx context.Context) error {
	tx, err := w.DB.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	events, err := tx.IntegrationEvent.Query().Where(integrationevent.DispatchedEQ(false)).Order(ent.Asc(integrationevent.FieldOccurredAt)).Limit(100).Where(func(s *sql.Selector) { s.ForUpdate(sql.WithLockAction(sql.SkipLocked)) }).All(ctx)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return tx.Commit()
	}
	// 停用的集成不再生成投递；停用前已排队的由发送前复核取消，重新启用也不补发
	enabled, err := tx.Integration.Query().Where(entintegration.EnabledEQ(true)).IDs(ctx)
	if err != nil {
		return err
	}
	subscriptions, err := tx.IntegrationSubscription.Query().Where(integrationsubscription.IntegrationIDIn(enabled...)).All(ctx)
	if err != nil {
		return err
	}
	for _, e := range events {
		for _, s := range subscriptions {
			config, found := configAt(s, e.OccurredAt)
			if s.Deleted || !found || !activeAt(s, e.OccurredAt) || !slices.Contains(config.Kinds, e.Kind) || !covers(config.GroupIDs, e.GroupIds) {
				continue
			}
			// 分发资格按发生时区间判断；当前暂停会保留待投递，发送前再核验。
			err = tx.IntegrationDelivery.Create().SetSubscriptionID(s.ID).SetEventID(e.ID).SetTargetURL(config.URL).SetTargetVersion(config.Version).SetSecret(config.Secret).SetKeyID(config.KeyID).Exec(ctx)
			if err != nil {
				return err
			}
		}
		if err = tx.IntegrationEvent.UpdateOne(e).SetDispatched(true).Exec(ctx); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (w *Worker) claim(ctx context.Context) (*ent.IntegrationDelivery, error) {
	tx, err := w.DB.Tx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now()
	// 暂停订阅的积压原地保留、不参与领取，不会堵住其他订阅；恢复后照常领取。
	// 集成停用不算暂停：照常领取，发送前的授权复核会把它标为 cancelled_scope。
	paused, err := tx.IntegrationSubscription.Query().Where(integrationsubscription.EnabledEQ(false), integrationsubscription.DeletedEQ(false)).IDs(ctx)
	if err != nil {
		return nil, err
	}
	row, err := tx.IntegrationDelivery.Query().Where(integrationdelivery.Or(
		integrationdelivery.And(integrationdelivery.StatusEQ("pending"), integrationdelivery.NextAtLTE(now)),
		integrationdelivery.And(integrationdelivery.StatusEQ("sending"), integrationdelivery.LeaseUntilLTE(now)),
	), integrationdelivery.SubscriptionIDNotIn(paused...)).Order(ent.Asc(integrationdelivery.FieldNextAt)).Where(func(s *sql.Selector) { s.ForUpdate(sql.WithLockAction(sql.SkipLocked)) }).First(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	row, err = tx.IntegrationDelivery.UpdateOne(row).SetStatus("sending").SetLeaseUntil(now.Add(30 * time.Second)).AddLeaseGeneration(1).AddAttempts(1).Save(ctx)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return row, nil
}
func (w *Worker) authorized(ctx context.Context, d *ent.IntegrationDelivery, e *ent.IntegrationEvent) (bool, error) {
	sub, err := w.DB.IntegrationSubscription.Get(ctx, d.SubscriptionID)
	if ent.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	i, err := w.DB.Integration.Get(ctx, sub.IntegrationID)
	if ent.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if sub.Deleted || !sub.Enabled || !i.Enabled || !slices.Contains(i.Scopes, "incidents:read") {
		return false, nil
	}
	if _, err = w.DB.User.Get(ctx, i.OwnerID); ent.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	grants, err := w.DB.IntegrationGroup.Query().Where(integrationgroup.IntegrationIDEQ(i.ID)).All(ctx)
	if err != nil {
		return false, err
	}
	ids := []uuid.UUID{}
	allowed := []string{}
	for _, g := range grants {
		if slices.Contains(sub.GroupIds, g.GroupID.String()) {
			ids = append(ids, g.GroupID)
		}
	}
	ids, err = w.DB.Group.Query().Where(group.IDIn(ids...)).IDs(ctx)
	if err != nil {
		return false, err
	}
	for _, id := range ids {
		allowed = append(allowed, id.String())
	}
	if !covers(allowed, e.GroupIds) {
		return false, nil
	}
	if e.Kind == "integration.test" {
		return true, nil
	}
	return w.DB.Incident.Query().Where(incident.IDEQ(e.IncidentID)).Where(incidentScope(ids)...).Exist(ctx)
}
func (w *Worker) deliver(ctx context.Context, d *ent.IntegrationDelivery) error {
	start := time.Now()
	sub, err := w.DB.IntegrationSubscription.Get(ctx, d.SubscriptionID)
	if err != nil && !ent.IsNotFound(err) {
		return err
	}
	if sub != nil && !sub.Deleted && !sub.Enabled {
		return w.DB.IntegrationDelivery.Update().Where(integrationdelivery.IDEQ(d.ID), integrationdelivery.StatusEQ("sending"), integrationdelivery.LeaseGenerationEQ(d.LeaseGeneration)).SetStatus("pending").SetNextAt(start.Add(time.Minute)).ClearLeaseUntil().AddAttempts(-1).Exec(ctx)
	}
	e, err := w.DB.IntegrationEvent.Get(ctx, d.EventID)
	if ent.IsNotFound(err) {
		return w.finish(ctx, d, start, 0, "cancelled_scope", "原消息已清理", 0)
	}
	if err != nil {
		return err
	}
	allowed, err := w.authorized(ctx, d, e)
	if err != nil {
		return err
	}
	if !allowed {
		return w.finish(ctx, d, start, 0, "cancelled_scope", "资源或授权已变化", 0)
	}
	if d.Attempts > 20 || start.Sub(d.RetryWindowAt) > 24*time.Hour {
		return w.finish(ctx, d, start, 0, "dead", "超过重试窗口，可能已被对方接收", 0)
	}
	if _, err = ValidateTarget(d.TargetURL); err != nil {
		return w.finish(ctx, d, start, 0, "dead", "目标 URL 无效", 0)
	}
	secret, err := w.Vault.Open(d.Secret, "integration-subscription:"+d.SubscriptionID.String())
	if err != nil {
		return w.finish(ctx, d, start, 0, "dead", "签名密钥不可解密", 0)
	}
	key, err := base64.StdEncoding.DecodeString(secret.Password)
	if err != nil || len(key) != 32 {
		return w.finish(ctx, d, start, 0, "dead", "签名密钥无效", 0)
	}
	defer clear(key)
	req, err := http.NewRequestWithContext(ctx, "POST", d.TargetURL, strings.NewReader(string(e.Payload)))
	if err != nil {
		return err
	}
	timestamp := strconv.FormatInt(start.Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-OpenXDR-Event-ID", e.ID.String())
	req.Header.Set("X-OpenXDR-Timestamp", timestamp)
	req.Header.Set("X-OpenXDR-Key-ID", d.KeyID)
	req.Header.Set("X-OpenXDR-Signature", SignEvent(key, timestamp, e.ID.String(), e.Payload))
	transport := w.Policy.transport()
	if w.transport != nil {
		transport = w.transport()
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return w.finish(ctx, d, start, 0, "pending", "网络或超时错误，可能已被对方接收", 0)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	code := response.StatusCode
	if code >= 200 && code < 300 {
		return w.finish(ctx, d, start, code, "delivered", "", 0)
	}
	if code == 408 || code == 429 || code >= 500 {
		retry := time.Duration(0)
		if seconds, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil && seconds > 0 {
			retry = time.Duration(min(seconds, 3600)) * time.Second
		} else if until, dateErr := http.ParseTime(response.Header.Get("Retry-After")); dateErr == nil {
			retry = max(0, min(time.Hour, time.Until(until)))
		}
		return w.finish(ctx, d, start, code, "pending", fmt.Sprintf("HTTP %d，可能已被对方接收", code), retry)
	}
	return w.finish(ctx, d, start, code, "dead", fmt.Sprintf("HTTP %d，需修正目标配置", code), 0)
}
func (w *Worker) finish(ctx context.Context, d *ent.IntegrationDelivery, start time.Time, code int, state, message string, retry time.Duration) error {
	now := time.Now()
	if state == "pending" && (d.Attempts >= 20 || now.Sub(d.RetryWindowAt) >= 24*time.Hour) {
		state = "dead"
	}
	delay := time.Duration(min(3600, 10*(1<<min(d.Attempts-1, 9)))) * time.Second
	// UUID 低位给退避加抖动，避免所有失败目标同时恢复。
	jitter := uuid.New()[15]
	delay += time.Duration(jitter) * delay / 1024
	delay = min(delay, time.Hour)
	delay = max(delay, retry)
	tx, err := w.DB.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	update := tx.IntegrationDelivery.Update().Where(integrationdelivery.IDEQ(d.ID), integrationdelivery.StatusEQ("sending"), integrationdelivery.LeaseGenerationEQ(d.LeaseGeneration)).SetStatus(state).SetLastError(message).ClearLeaseUntil()
	if state == "pending" {
		update.SetNextAt(minTime(now.Add(delay), d.RetryWindowAt.Add(24*time.Hour)))
	} else {
		update.SetCompletedAt(now)
	}
	n, err := update.Save(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	if err = tx.IntegrationAttempt.Create().SetDeliveryID(d.ID).SetStartedAt(start).SetEndedAt(now).SetHTTPStatus(code).SetResult(state).SetLeaseGeneration(d.LeaseGeneration).Exec(ctx); err != nil {
		return err
	}
	return tx.Commit()
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
