//go:build integration

package ingest

import (
	"context"
	"encoding/json"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
)

const accountRule = "id: by-account\nkind: event_count\ngroup_by: account\nwithin: 1m\nrules: [base]\nthreshold: 3\nlevel: high\n"
const assetRule = "id: by-asset\nkind: event_count\nwithin: 1m\nrules: [base]\nthreshold: 3\n"

type accountFixture struct {
	t       *testing.T
	p       *Processor
	client  *ent.Client
	now     time.Time
	metrics *capacityMetrics
}

func newAccountFixture(t *testing.T) *accountFixture {
	p, client, db := testProcessor(t)
	t.Cleanup(func() { client.Close(); db.Close() })
	p.Temporal = temporalStoreFixtureWithRule(t, accountRule, assetRule)
	metrics := &capacityMetrics{}
	p.Metrics = metrics
	return &accountFixture{t: t, p: p, client: client, now: time.Now().UTC().Truncate(time.Microsecond), metrics: metrics}
}

func (f *accountFixture) asset(group uuid.UUID) uuid.UUID {
	f.t.Helper()
	return f.client.Asset.Create().SetHostname("account-" + uuid.NewString()[:8]).SetGroupID(group).SaveX(context.Background()).ID
}

func (f *accountFixture) event(asset uuid.UUID, seconds int, username string) Envelope {
	return Envelope{Version: EnvelopeVersion, ID: uuid.New(), PartitionKey: asset.String(), Timestamp: f.now.Add(time.Duration(seconds) * time.Second),
		ClassUID: 1007, Source: "agent", AssetID: &asset, Username: username, Raw: json.RawMessage(`{"marker":"yes"}`)}
}

func (f *accountFixture) process(events ...Envelope) {
	f.t.Helper()
	for _, e := range events {
		if err := f.p.Process(context.Background(), e); err != nil {
			f.t.Fatal(err)
		}
	}
}

func (f *accountFixture) detections(rule string) int {
	f.t.Helper()
	var n int
	if err := f.p.DB.QueryRow(`SELECT count(*) FROM temporal_detections WHERE rule_id=$1`, rule).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// 同组同账号跨主机累计；用户名大小写/空白不同归为同一账号；告警绑定终点事件的资产。
func TestTemporalAccountAccumulatesAcrossAssets(t *testing.T) {
	f := newAccountFixture(t)
	group := uuid.New()
	a1, a2 := f.asset(group), f.asset(group)
	first, second, last := f.event(a1, 0, "Alice"), f.event(a2, 1, "alice "), f.event(a1, 2, "ALICE")
	// 终点先到，前序迟到补齐；全部重投不增加命中。
	f.process(last, second, first, first, second, last)
	if f.detections("by-asset") != 0 {
		t.Fatal("单主机未达阈值不应出资产维度命中")
	}
	var entity string
	var evidence []byte
	var alertAsset, anchor uuid.UUID
	var count int
	if err := f.p.DB.QueryRow(`SELECT d.entity,d.evidence,d.anchor_id,a.asset_id,a.count FROM temporal_detections d JOIN alerts a ON a.id=d.alert_id WHERE d.rule_id='by-account'`).
		Scan(&entity, &evidence, &anchor, &alertAsset, &count); err != nil {
		t.Fatal(err)
	}
	var ids []uuid.UUID
	if err := json.Unmarshal(evidence, &ids); err != nil {
		t.Fatal(err)
	}
	if entity != "account:alice" || anchor != last.ID || alertAsset != a1 || count != 1 || !slices.Equal(ids, []uuid.UUID{first.ID, second.ID, last.ID}) {
		t.Fatalf("账号命中错误: entity=%s anchor=%s asset=%s count=%d evidence=%v", entity, anchor, alertAsset, count, ids)
	}
	var linked int
	if err := f.p.DB.QueryRow(`SELECT count(*) FROM temporal_evidence WHERE rule_id='by-account' AND event_id = ANY($1)`, []uuid.UUID{first.ID, second.ID}).Scan(&linked); err != nil || linked != 2 {
		t.Fatalf("跨主机前序证据未保护: %d %v", linked, err)
	}
	// 不同账号不累计
	other := f.asset(group)
	f.process(f.event(other, 10, "bob"), f.event(a1, 11, "carol"), f.event(a2, 12, "dave"))
	if f.detections("by-account") != 1 {
		t.Fatal("不同账号被累计")
	}
}

// 不同组同名账号互相隔离：组是授权边界。
func TestTemporalAccountIsolatedByGroup(t *testing.T) {
	f := newAccountFixture(t)
	g1, g2 := uuid.New(), uuid.New()
	a1, a2, b1 := f.asset(g1), f.asset(g1), f.asset(g2)
	f.process(f.event(a1, 0, "admin"), f.event(b1, 1, "admin"), f.event(a2, 2, "admin"))
	if f.detections("by-account") != 0 {
		t.Fatal("账号计数跨组累计")
	}
	f.process(f.event(a2, 3, "admin"))
	if f.detections("by-account") != 1 {
		t.Fatal("同组第三次应命中")
	}
}

// 资产换组（A→B→A）清除其候选，账号维度也不复用换组前的事件。
func TestTemporalAccountGroupRoundTripResets(t *testing.T) {
	f := newAccountFixture(t)
	group := uuid.New()
	a1, a2 := f.asset(group), f.asset(group)
	f.process(f.event(a1, 0, "admin"), f.event(a1, 1, "admin"))
	ctx := context.Background()
	f.client.Asset.UpdateOneID(a1).SetGroupID(uuid.New()).ExecX(ctx)
	f.client.Asset.UpdateOneID(a1).SetGroupID(group).ExecX(ctx)
	f.process(f.event(a2, 2, "admin"))
	if f.detections("by-account") != 0 {
		t.Fatal("换组周期前的候选被账号维度复用")
	}
	f.process(f.event(a2, 3, "admin"), f.event(a1, 4, "admin"))
	if f.detections("by-account") != 1 {
		t.Fatal("换组后新事件应重新累计")
	}
}

// 无用户名事件不参与账号规则并计入 no_account；资产维度照常。
func TestTemporalAccountRequiresUsername(t *testing.T) {
	f := newAccountFixture(t)
	asset := f.asset(uuid.New())
	f.process(f.event(asset, 0, ""), f.event(asset, 1, " "), f.event(asset, 2, ""))
	if f.detections("by-account") != 0 || f.detections("by-asset") != 1 {
		t.Fatal("无用户名事件被归入账号或影响资产维度")
	}
	if len(f.metrics.reasons) != 3 || slices.ContainsFunc(f.metrics.reasons, func(r string) bool { return r != "no_account" }) {
		t.Fatalf("no_account 缺口未逐条计数: %v", f.metrics.reasons)
	}
	var accounts int
	if err := f.p.DB.QueryRow(`SELECT count(*) FROM temporal_candidates WHERE account IS NOT NULL`).Scan(&accounts); err != nil || accounts != 0 {
		t.Fatalf("空用户名写成了账号: %d %v", accounts, err)
	}
}

// 不同资产（不同队列分片）并发处理同一账号：恰好阈值条数时，无论到达顺序，
// 最后提交的事务都必须看到另外两条；没有账号锁时两个事务可能互相看不到而漏报。
func TestTemporalAccountConcurrentAssets(t *testing.T) {
	f := newAccountFixture(t)
	group := uuid.New()
	for round := range 5 {
		account := "svc-" + uuid.NewString()
		var events []Envelope
		for i := range 3 {
			events = append(events, f.event(f.asset(group), round*100+i, account))
		}
		var wg sync.WaitGroup
		errs := make(chan error, len(events))
		for _, e := range events {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs <- f.p.Process(context.Background(), e)
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		var anchor uuid.UUID
		if err := f.p.DB.QueryRow(`SELECT anchor_id FROM temporal_detections WHERE rule_id='by-account' AND entity=$1`, "account:"+account).Scan(&anchor); err != nil || anchor != events[2].ID {
			t.Fatalf("第 %d 轮并发跨资产漏报或终点错误: %s %v", round, anchor, err)
		}
	}
}

// min_assets: 2：单台资产再多次也不出账号命中（交给资产规则）；迟到的第二台资产事件
// 使不同资产数达标时，命中落在越过的那一刻，重启重投不重复。
func TestTemporalAccountMinAssetsWithLateEvent(t *testing.T) {
	p, client, db := testProcessor(t)
	t.Cleanup(func() { client.Close(); db.Close() })
	rule := "id: spread\nkind: event_count\ngroup_by: account\nmin_assets: 2\nwithin: 1m\nrules: [base]\nthreshold: 3\n"
	p.Temporal = temporalStoreFixtureWithRule(t, rule, assetRule)
	f := &accountFixture{t: t, p: p, client: client, now: time.Now().UTC().Truncate(time.Microsecond), metrics: &capacityMetrics{}}
	group := uuid.New()
	a1, a2 := f.asset(group), f.asset(group)
	first, second, fourth := f.event(a1, 0, "ops"), f.event(a1, 10, "ops"), f.event(a1, 30, "ops")
	f.process(first, second, fourth)
	if f.detections("spread") != 0 || f.detections("by-asset") != 1 {
		t.Fatal("单台资产三次失败应只命中资产规则")
	}
	late := f.event(a2, 20, "OPS")
	f.process(late)
	var anchor, alertAsset uuid.UUID
	var evidence []byte
	if err := db.QueryRow(`SELECT d.anchor_id,d.evidence,a.asset_id FROM temporal_detections d JOIN alerts a ON a.id=d.alert_id WHERE d.rule_id='spread'`).Scan(&anchor, &evidence, &alertAsset); err != nil {
		t.Fatal(err)
	}
	var ids []uuid.UUID
	if err := json.Unmarshal(evidence, &ids); err != nil {
		t.Fatal(err)
	}
	if anchor != late.ID || alertAsset != a2 || !slices.Equal(ids, []uuid.UUID{first.ID, second.ID, late.ID}) {
		t.Fatalf("迟到资产达标的命中错误: anchor=%s asset=%s evidence=%v", anchor, alertAsset, ids)
	}
	// 处理器重建后全部重投：不重复命中，之后的终点前序已满足也不再出命中
	restarted := *p
	restarted.Temporal = temporalStoreFixtureWithRule(t, rule, assetRule)
	f.p = &restarted
	f.process(first, second, late, fourth, f.event(a2, 40, "ops"))
	if n := f.detections("spread"); n != 1 {
		t.Fatalf("重投或持续失败重复命中: %d", n)
	}
}
