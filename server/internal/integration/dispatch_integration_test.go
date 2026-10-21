//go:build integration

package integration

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/integrationdelivery"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/testdb"
)

func TestSubscriptionHistoryAndConcurrentClaim(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Now()
	start, pause, resume := now.Add(-4*time.Hour), now.Add(-3*time.Hour), now.Add(-time.Hour)
	group := uuid.New().String()
	owner := db.User.Create().SetUsername("owner").SetPasswordHash("x").SetRole("admin").SaveX(ctx)
	i := db.Integration.Create().SetName("tickets").SetPurpose("test").SetOwnerID(owner.ID).SetEnabled(true).SetScopes([]string{"incidents:read"}).SaveX(ctx)
	old := schema.SubscriptionConfig{From: start, To: &resume, URL: "https://old.example.test", Version: 1, GroupIDs: []string{group}, Kinds: []string{"incident.created"}, Secret: []byte{}, KeyID: "old"}
	current := old
	current.From, current.To, current.URL, current.Version = resume, nil, "https://new.example.test", 2
	sub := db.IntegrationSubscription.Create().SetIntegrationID(i.ID).SetName("tickets").SetURL(current.URL).SetVersion(2).SetEnabled(true).SetGroupIds([]string{group}).SetKinds(old.Kinds).SetSecret([]byte{}).SetKeyID("current").SetPeriods([]schema.SubscriptionPeriod{{From: start, To: &pause}, {From: resume}}).SetConfigurations([]schema.SubscriptionConfig{old, current}).SaveX(ctx)
	for _, at := range []time.Time{start.Add(-time.Minute), start.Add(time.Minute), pause.Add(time.Minute), resume.Add(time.Minute)} {
		db.IntegrationEvent.Create().SetIncidentID(uuid.New()).SetRevision(1).SetKind("incident.created").SetOccurredAt(at).SetGroupIds([]string{group}).SetPayload(json.RawMessage(`{}`)).ExecX(ctx)
	}
	w := &Worker{DB: db}
	if err := w.dispatch(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.dispatch(ctx); err != nil {
		t.Fatal(err)
	}
	rows := db.IntegrationDelivery.Query().AllX(ctx)
	if len(rows) != 2 {
		t.Fatalf("历史或暂停期间事件被补发，或重复分发: %d", len(rows))
	}
	versions := map[int64]string{}
	for _, d := range rows {
		versions[d.TargetVersion] = d.TargetURL
	}
	if versions[1] != old.URL || versions[2] != current.URL {
		t.Fatal("积压丢失发生时目标版本", versions)
	}
	db.IntegrationSubscription.UpdateOne(sub).SetEnabled(false).ExecX(ctx)
	if got, err := w.claim(ctx); err != nil || got != nil {
		t.Fatal("暂停订阅仍领取投递", got, err)
	}
	db.IntegrationSubscription.UpdateOne(sub).SetEnabled(true).ExecX(ctx)
	db.IntegrationDelivery.Update().SetNextAt(now.Add(-time.Minute)).ExecX(ctx)
	type result struct {
		row *ent.IntegrationDelivery
		err error
	}
	results := make(chan result, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); d, err := w.claim(ctx); results <- result{d, err} }()
	}
	wg.Wait()
	close(results)
	claimed := map[uuid.UUID]bool{}
	for r := range results {
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.row == nil {
			continue
		}
		if claimed[r.row.ID] {
			t.Fatal("并发 worker 领取同一有效租约")
		}
		claimed[r.row.ID] = true
	}
	if len(claimed) != 2 {
		t.Fatal("恢复后未领取积压", len(claimed))
	}
}

// 暂停订阅的积压不能堵住其他订阅；集成停用后不再分发，已排队的取消而不是等重新启用补发。
func TestPausedBacklogAndDisabledIntegration(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Now()
	group := uuid.New().String()
	owner := db.User.Create().SetUsername("owner").SetPasswordHash("x").SetRole("admin").SaveX(ctx)
	subscribe := func(name string) *ent.IntegrationSubscription {
		i := db.Integration.Create().SetName(name).SetPurpose("test").SetOwnerID(owner.ID).SetEnabled(true).SetScopes([]string{"incidents:read"}).SaveX(ctx)
		return db.IntegrationSubscription.Create().SetIntegrationID(i.ID).SetName(name).SetURL("https://" + name + ".example.test").SetVersion(1).SetEnabled(true).SetGroupIds([]string{group}).SetKinds([]string{"incident.created"}).SetSecret([]byte{}).SetKeyID(name).SetPeriods([]schema.SubscriptionPeriod{{From: now.Add(-time.Hour)}}).SaveX(ctx)
	}
	queue := func(sub *ent.IntegrationSubscription, at time.Time) *ent.IntegrationDelivery {
		e := db.IntegrationEvent.Create().SetIncidentID(uuid.New()).SetRevision(1).SetKind("incident.created").SetOccurredAt(at).SetGroupIds([]string{group}).SetPayload(json.RawMessage(`{}`)).SetDispatched(true).SaveX(ctx)
		return db.IntegrationDelivery.Create().SetSubscriptionID(sub.ID).SetEventID(e.ID).SetTargetURL(sub.URL).SetTargetVersion(1).SetSecret([]byte{}).SetKeyID(sub.KeyID).SetNextAt(at).SaveX(ctx)
	}
	paused, healthy, off := subscribe("paused"), subscribe("healthy"), subscribe("off")
	db.IntegrationSubscription.UpdateOne(paused).SetEnabled(false).ExecX(ctx)
	for i := range 150 {
		queue(paused, now.Add(-time.Hour+time.Duration(i)*time.Millisecond))
	}
	want := queue(healthy, now.Add(-time.Minute))
	w := &Worker{DB: db}
	got, err := w.claim(ctx)
	if err != nil || got == nil || got.ID != want.ID {
		t.Fatalf("暂停订阅的积压堵住了健康订阅: %v %v", got, err)
	}

	db.Integration.UpdateOneID(off.IntegrationID).SetEnabled(false).ExecX(ctx)
	queued := queue(off, now.Add(-2*time.Hour))
	db.IntegrationEvent.Create().SetIncidentID(uuid.New()).SetRevision(1).SetKind("incident.created").SetOccurredAt(now).SetGroupIds([]string{group}).SetPayload(json.RawMessage(`{}`)).ExecX(ctx)
	if err := w.dispatch(ctx); err != nil {
		t.Fatal(err)
	}
	if n := db.IntegrationDelivery.Query().Where(integrationdelivery.SubscriptionIDEQ(off.ID)).CountX(ctx); n != 1 {
		t.Fatalf("停用集成仍在生成投递: %d", n)
	}
	d, err := w.claim(ctx)
	if err != nil || d == nil || d.ID != queued.ID {
		t.Fatalf("停用集成的积压应被领取后取消: %v %v", d, err)
	}
	if err := w.deliver(ctx, d); err != nil {
		t.Fatal(err)
	}
	if status := db.IntegrationDelivery.GetX(ctx, queued.ID).Status; status != "cancelled_scope" {
		t.Fatalf("停用集成的积压未取消: %s", status)
	}
}
