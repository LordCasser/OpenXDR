//go:build integration

package identity

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/identity/directory"
	"openxdr/server/internal/testdb"
)

const (
	sidAlice   = "S-1-5-21-1004336348-1177238915-682003330-1001"
	sidLocal   = "S-1-5-21-1004336348-1177238915-682003330-1002"
	sidTwinned = "S-1-5-21-1004336348-1177238915-682003330-1003"
)

type graphFixture struct {
	t   *testing.T
	ctx context.Context
	db  *sql.DB
}

func newGraphFixture(t *testing.T) (*graphFixture, func(name string) uuid.UUID, func(group uuid.UUID, host, os string) uuid.UUID) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	group := func(name string) uuid.UUID { return client.Group.Create().SetName(name).SaveX(ctx).ID }
	asset := func(group uuid.UUID, host, os string) uuid.UUID {
		return client.Asset.Create().SetHostname(host).SetOs(os).SetGroupID(group).SaveX(ctx).ID
	}
	return &graphFixture{t, ctx, db}, group, asset
}

// event 走生产入库路径：插入原始事件后在同一事务里调用身份观察。
func (f *graphFixture) event(asset uuid.UUID, ts time.Time, class int, raw string) uuid.UUID {
	f.t.Helper()
	id := uuid.New()
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO events(id,ts,class_uid,source,asset_id,raw) VALUES($1,$2,$3,'agent',$4,$5::jsonb)`, id, ts, class, asset, raw); err != nil {
		f.t.Fatal(err)
	}
	for _, observe := range []func(context.Context, *sql.Tx, uuid.UUID) error{ObserveWindows, ObserveLinuxLogin, ObserveLinuxAccounts} {
		if err := observe(f.ctx, tx, id); err != nil {
			f.t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *graphFixture) sync() {
	f.t.Helper()
	if _, err := SyncGraph(f.ctx, f.db); err != nil {
		f.t.Fatal(err)
	}
}

func (f *graphFixture) one(query string, args ...any) string {
	f.t.Helper()
	var value sql.NullString
	if err := f.db.QueryRow(query, args...).Scan(&value); err != nil {
		f.t.Fatalf("%s: %v", query, err)
	}
	return value.String
}

func (f *graphFixture) adSource(group uuid.UUID, authority string, accounts ...directory.Account) {
	f.t.Helper()
	source := directory.Source{ID: uuid.New(), GroupID: group, Kind: "ad", Authority: authority}
	if err := directory.RegisterSource(f.ctx, f.db, source); err != nil {
		f.t.Fatal(err)
	}
	start := time.Now().UTC().Add(-time.Minute)
	if err := directory.SaveScan(f.ctx, f.db, directory.Scan{Source: source, StartedAt: start, FinishedAt: start.Add(time.Second), Accounts: accounts}); err != nil {
		f.t.Fatal(err)
	}
}

func windowsLogin(sid, name string) string {
	return `{"event_id":4624,"log_name":"Security","activity_id":1,"status_id":1,"user":{"uid":"` + sid + `","name":"` + name + `","domain":"CORP"},"src_endpoint":{"ip":"10.0.0.5"}}`
}

func linuxLogin(name string, success bool) string {
	status := "2"
	if success {
		status = "1"
	}
	return `{"activity_id":1,"status_id":` + status + `,"user":{"name":"` + name + `"},"src_endpoint":{"ip":"192.0.2.7"},"service":{"name":"pts/0"}}`
}

const passwd = `{"activity_id":2,"device":{"local_accounts":{"version":1,"source":"etc-passwd","state":"observed","items":[{"name":"root","uid":0,"gid":0,"shell":"/bin/bash"},{"name":"alice","uid":1000,"gid":1000,"shell":"/bin/bash"}]}}}`

func TestGraphStrongEvidenceOnly(t *testing.T) {
	f, newGroup, newAsset := newGraphFixture(t)
	g := newGroup("graph")
	other := newGroup("other")
	win := newAsset(g, "win1", "windows")
	lin := newAsset(g, "lin1", "linux")
	otherLin := newAsset(other, "lin-other", "linux")
	f.adSource(g, "ldaps://dc1.example.invalid/DC=corp", directory.Account{ExternalID: "a", Username: "alice", WindowsSID: sidAlice},
		directory.Account{ExternalID: "t1", Username: "twin", WindowsSID: sidTwinned})
	f.adSource(g, "ldaps://dc2.example.invalid/DC=corp", directory.Account{ExternalID: "t2", Username: "twin", WindowsSID: sidTwinned})
	// 别组目录有同 SID 账号，也不能链接
	f.adSource(other, "ldaps://dc9.example.invalid/DC=corp", directory.Account{ExternalID: "x", Username: "alice", WindowsSID: sidLocal})

	now := time.Now().UTC().Truncate(time.Microsecond)
	f.event(win, now.Add(-time.Hour), 3002, windowsLogin(sidAlice, "alice"))
	f.event(win, now.Add(-time.Hour), 3002, windowsLogin(sidLocal, "alice"))
	f.event(win, now.Add(-time.Hour), 3002, windowsLogin(sidTwinned, "twin"))
	f.event(lin, now.Add(-3*time.Hour), 5001, passwd)
	f.event(otherLin, now.Add(-3*time.Hour), 5001, passwd)
	matched := f.event(lin, now.Add(-2*time.Hour), 3002, linuxLogin("alice", true))
	missing := f.event(lin, now.Add(-2*time.Hour), 3002, linuxLogin("mallory", false))
	f.sync()

	link := func(key string) (basis, identityKind, anchorKind string) {
		t.Helper()
		err := f.db.QueryRow(`SELECT l.basis,i.kind,anchor.kind FROM identity_accounts a
 JOIN identity_links l ON l.account_id=a.id AND l.revoked_at IS NULL JOIN identities i ON i.id=l.identity_id
 JOIN identity_accounts anchor ON anchor.id=i.anchor_account_id WHERE a.account_key=$1`, key).Scan(&basis, &identityKind, &anchorKind)
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		return
	}
	winKey := func(sid string) string { return "windows-sid:" + g.String() + ":" + win.String() + ":" + sid }
	if basis, kind, anchor := link(winKey(sidAlice)); basis != "ad_sid" || kind != "directory" || anchor != "directory" {
		t.Fatalf("SID 与 objectSid 一致应链到目录身份: %s %s %s", basis, kind, anchor)
	}
	if basis, kind, anchor := link(winKey(sidLocal)); basis != "host_local" || kind != "host" || anchor != "windows" {
		t.Fatalf("同名不同 SID 不得合并: %s %s %s", basis, kind, anchor)
	}
	if basis, _, _ := link(winKey(sidTwinned)); basis != "host_local" {
		t.Fatalf("多个目录候选应视为歧义: %s", basis)
	}
	if f.one(`SELECT l.evidence->>'ambiguousDirectoryMatches' FROM identity_links l JOIN identity_accounts a ON a.id=l.account_id WHERE a.account_key=$1`, winKey(sidTwinned)) != "2" {
		t.Fatal("歧义证据没有记录")
	}
	if f.one(`SELECT l.evidence->'directory'->>'objectSid' FROM identity_links l JOIN identity_accounts a ON a.id=l.account_id WHERE a.account_key=$1`, winKey(sidAlice)) != sidAlice {
		t.Fatal("SID 链接缺少证据")
	}
	// 两台 Linux 上的同名 alice 各自独立，且不会与目录 alice 合并
	if f.one(`SELECT count(DISTINCT l.identity_id) FROM identity_accounts a JOIN identity_links l ON l.account_id=a.id AND l.revoked_at IS NULL WHERE a.name='alice'`) != "5" {
		t.Fatal("同名账号被自动合并")
	}
	if f.one(`SELECT count(*) FROM identity_links l JOIN identities i ON i.id=l.identity_id JOIN identity_accounts a ON a.id=l.account_id WHERE i.group_id<>a.group_id`) != "0" {
		t.Fatal("出现跨组链接")
	}
	if state := f.one(`SELECT state||':'||uid FROM identity_login_matches WHERE event_id=$1`, matched); state != "matched:1000" {
		t.Fatalf("Linux 登录未关联当时清单: %s", state)
	}
	if state := f.one(`SELECT state FROM identity_login_matches WHERE event_id=$1`, missing); state != "no_account" {
		t.Fatalf("清单中没有的账号应标未匹配: %s", state)
	}

	// 幂等：重跑不新增、不撤销
	before := f.one(`SELECT count(*)||'/'||count(*) FILTER (WHERE revoked_at IS NULL) FROM identity_links`)
	f.sync()
	if after := f.one(`SELECT count(*)||'/'||count(*) FILTER (WHERE revoked_at IS NULL) FROM identity_links`); after != before {
		t.Fatalf("重跑改变了链接: %s → %s", before, after)
	}

	// 迟到的清单：登录前 30 分钟的快照里没有 alice，登录改为未匹配
	f.event(lin, now.Add(-150*time.Minute), 5001, `{"activity_id":2,"device":{"local_accounts":{"version":1,"source":"etc-passwd","state":"observed","items":[{"name":"root","uid":0,"gid":0,"shell":"/bin/bash"}]}}}`)
	f.sync()
	if state := f.one(`SELECT state FROM identity_login_matches WHERE event_id=$1`, matched); state != "no_account" {
		t.Fatalf("迟到清单未触发重算: %s", state)
	}
	// 当时清单不可用就不往前猜
	f.event(lin, now.Add(-90*time.Minute), 5001, `{"activity_id":2,"device":{"local_accounts":{"version":1,"source":"etc-passwd","state":"unavailable"}}}`)
	unavailable := f.event(lin, now.Add(-80*time.Minute), 3002, linuxLogin("alice", true))
	noSnapshot := f.event(otherLin, now.Add(-30*time.Hour), 3002, linuxLogin("alice", true))
	f.sync()
	if state := f.one(`SELECT state FROM identity_login_matches WHERE event_id=$1`, unavailable); state != "snapshot_unavailable" {
		t.Fatalf("清单不可用时不应匹配: %s", state)
	}
	if state := f.one(`SELECT state FROM identity_login_matches WHERE event_id=$1`, noSnapshot); state != "no_snapshot" {
		t.Fatalf("窗口内没有清单应标 no_snapshot: %s", state)
	}

	// 目录 SID 变化：alice 的 objectSid 被清掉后，Windows 账号回到主机内身份，旧链接留痕
	src := f.one(`SELECT source_id FROM identity_directory_accounts WHERE windows_sid=$1`, sidAlice)
	var source directory.Source
	if err := f.db.QueryRow(`SELECT id,group_id,kind,authority FROM identity_directory_sources WHERE id=$1`, src).Scan(&source.ID, &source.GroupID, &source.Kind, &source.Authority); err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC()
	if err := directory.SaveScan(f.ctx, f.db, directory.Scan{Source: source, StartedAt: start, FinishedAt: start, Accounts: []directory.Account{{ExternalID: "a", Username: "alice"}}}); err != nil {
		t.Fatal(err)
	}
	f.sync()
	if basis, _, _ := link(winKey(sidAlice)); basis != "host_local" {
		t.Fatalf("证据消失后仍保留强链接: %s", basis)
	}
	if f.one(`SELECT revoke_reason FROM identity_links l JOIN identity_accounts a ON a.id=l.account_id WHERE a.account_key=$1 AND l.basis='ad_sid'`, winKey(sidAlice)) != "evidence_changed" {
		t.Fatal("撤销的链接没有留痕")
	}

	// 资产换组：旧组链接撤销，新组不继承旧观察
	if _, err := f.db.Exec(`UPDATE assets SET group_id=$1 WHERE id=$2`, other, win); err != nil {
		t.Fatal(err)
	}
	f.sync()
	if f.one(`SELECT count(*) FROM identity_links l JOIN identity_accounts a ON a.id=l.account_id WHERE a.asset_id=$1 AND l.revoked_at IS NULL`, win) != "0" {
		t.Fatal("换组后旧组仍有链接")
	}
	if f.one(`SELECT count(*) FROM identity_accounts WHERE asset_id=$1 AND group_id=$2`, win, other) != "0" {
		t.Fatal("新组继承了旧组观察")
	}
}
