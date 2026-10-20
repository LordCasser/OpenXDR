//go:build integration

package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/identity"
	"openxdr/server/internal/identity/directory"
	"openxdr/server/internal/testdb"
)

func TestIdentityGraphAPI(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := identity.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	g := client.Group.Create().SetName("graph-api").SaveX(ctx)
	other := client.Group.Create().SetName("graph-other").SaveX(ctx)
	lin1 := client.Asset.Create().SetHostname("lin1").SetOs("linux").SetGroupID(g.ID).SaveX(ctx)
	lin2 := client.Asset.Create().SetHostname("lin2").SetOs("linux").SetGroupID(g.ID).SaveX(ctx)
	foreign := client.Asset.Create().SetHostname("foreign").SetOs("linux").SetGroupID(other.ID).SaveX(ctx)
	user := func(name, role, memberRole string) *ent.User {
		u := client.User.Create().SetUsername(name).SetRole(role).SetPasswordHash("unused").SaveX(ctx)
		if memberRole != "" {
			client.GroupMember.Create().SetUserID(u.ID).SetGroupID(g.ID).SetRole(memberRole).SaveX(ctx)
		}
		return u
	}
	viewer := user("graph-viewer", "viewer", "viewer")
	analyst := user("graph-analyst", "analyst", "analyst")
	outsider := user("graph-outsider", "analyst", "")

	source := directory.Source{ID: uuid.New(), GroupID: g.ID, Kind: "keycloak", Authority: "https://sso.example.invalid/realms/corp"}
	if err := directory.RegisterSource(ctx, db, source); err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Add(-time.Minute)
	if err := directory.SaveScan(ctx, db, directory.Scan{Source: source, StartedAt: start, FinishedAt: start, Accounts: []directory.Account{{ExternalID: "1", Username: "Alice@corp.example"}}}); err != nil {
		t.Fatal(err)
	}
	event := func(asset uuid.UUID, ts time.Time, class int, raw string) uuid.UUID {
		t.Helper()
		id := uuid.New()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err := tx.Exec(`INSERT INTO events(id,ts,class_uid,source,asset_id,raw) VALUES($1,$2,$3,'agent',$4,$5::jsonb)`, id, ts, class, asset, raw); err != nil {
			t.Fatal(err)
		}
		if err := identity.ObserveLinuxLogin(ctx, tx, id); err != nil {
			t.Fatal(err)
		}
		if err := identity.ObserveLinuxAccounts(ctx, tx, id); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return id
	}
	now := time.Now().UTC()
	passwd := `{"activity_id":2,"device":{"local_accounts":{"version":1,"source":"etc-passwd","state":"observed","items":[{"name":"root","uid":0,"gid":0,"shell":"/bin/sh"},{"name":"alice","uid":1000,"gid":1000,"shell":"/bin/sh"},{"name":"daemon","uid":1,"gid":1,"shell":"/usr/sbin/nologin"},{"name":"svc","uid":998,"gid":998,"shell":"/bin/sh"}]}}}`
	for _, a := range []uuid.UUID{lin1.ID, lin2.ID, foreign.ID} {
		event(a, now.Add(-2*time.Hour), 5001, passwd)
	}
	event(lin1.ID, now.Add(-time.Hour), 3002, `{"activity_id":1,"status_id":1,"user":{"name":"alice"},"src_endpoint":{"ip":"192.0.2.7"},"service":{"name":"pts/0"}}`)
	event(lin1.ID, now.Add(-time.Hour), 3002, `{"activity_id":1,"status_id":2,"user":{"name":"mallory"},"src_endpoint":{"ip":"198.51.100.9"},"service":{"name":"ssh:notty"}}`)
	// 系统范围的 svc 只在 lin1 登录过：lin1 上的照常显示，lin2 上的和 daemon 一样默认不显示
	event(lin1.ID, now.Add(-time.Hour), 3002, `{"activity_id":1,"status_id":1,"user":{"name":"svc"},"src_endpoint":{"ip":"192.0.2.8"},"service":{"name":"pts/1"}}`)
	if _, err := identity.SyncGraph(ctx, db); err != nil {
		t.Fatal(err)
	}

	h := Identities(db)
	call := func(u *ent.User, method, path string, body any) (int, []byte) {
		t.Helper()
		var payload bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&payload).Encode(body)
		}
		w := httptest.NewRecorder()
		as(u, h).ServeHTTP(w, httptest.NewRequest(method, path, &payload).WithContext(context.Background()))
		return w.Code, w.Body.Bytes()
	}
	type listResult struct {
		Items     []identitySummary
		Truncated bool
	}
	list := func(u *ent.User, query string) listResult {
		t.Helper()
		code, body := call(u, "GET", "/api/identities?groupId="+g.ID.String()+query, nil)
		var result listResult
		if code != 200 || json.Unmarshal(body, &result) != nil {
			t.Fatalf("%d %s", code, body)
		}
		return result
	}
	if n := len(list(viewer, "").Items); n != 6 {
		t.Fatalf("默认应有目录 1 个、两台主机各 root 与 alice、lin1 上登录过的 svc: %d", n)
	}
	all := list(viewer, "&includeSystem=true").Items
	system := 0
	for _, item := range all {
		if item.System {
			system++
			if item.Name == nil || (*item.Name != "daemon" && *item.Name != "svc") {
				t.Errorf("不该标成系统账号: %+v", item)
			}
		}
	}
	if len(all) != 9 || system != 3 {
		t.Fatalf("含系统账号应 9 个、其中系统账号 3 个（两台的 daemon、lin2 的 svc）: %d %d", len(all), system)
	}
	if n := len(list(outsider, "").Items); n != 0 {
		t.Fatalf("组外用户看到了身份: %d", n)
	}
	found := list(viewer, "&q=alice&kind=directory")
	if len(found.Items) != 1 {
		t.Fatalf("搜索结果不对: %+v", found)
	}
	dirIdentity := found.Items[0].ID
	accountOn := func(asset uuid.UUID, name string) uuid.UUID {
		var id uuid.UUID
		if err := db.QueryRow(`SELECT id FROM identity_accounts WHERE asset_id=$1 AND name=$2`, asset, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	alice1, alice2, foreignAlice := accountOn(lin1.ID, "alice"), accountOn(lin2.ID, "alice"), accountOn(foreign.ID, "alice")

	candidates := func() []identityCandidateRow {
		t.Helper()
		code, body := call(viewer, "GET", "/api/identities/"+dirIdentity.String()+"/candidates", nil)
		var result struct{ Items []identityCandidateRow }
		if code != 200 || json.Unmarshal(body, &result) != nil {
			t.Fatalf("%d %s", code, body)
		}
		return result.Items
	}
	if c := candidates(); len(c) != 2 || c[0].Reason != "similar_name" || c[0].Direction != "incoming" {
		t.Fatalf("同名本地账号应作为候选而不是自动合并: %+v", c)
	}
	path := "/api/identities/" + dirIdentity.String()
	if code, _ := call(viewer, "POST", path+"/links", map[string]any{"accountId": alice1}); code != http.StatusForbidden {
		t.Fatalf("viewer 不能确认合并: %d", code)
	}
	if code, _ := call(outsider, "POST", path+"/links", map[string]any{"accountId": alice1}); code != http.StatusNotFound {
		t.Fatalf("组外用户应看不到身份: %d", code)
	}
	if code, _ := call(analyst, "POST", path+"/links", map[string]any{"accountId": foreignAlice}); code != http.StatusConflict {
		t.Fatalf("跨组账号不能合并: %d", code)
	}
	if code, body := call(analyst, "POST", path+"/links", map[string]any{"accountId": alice1}); code != http.StatusCreated {
		t.Fatalf("确认合并失败: %d %s", code, body)
	}
	var audits int
	if err := db.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='identity_link_confirmed' AND username='graph-analyst'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("确认没有审计: %d %v", audits, err)
	}
	// 后台重算不改写人工链接
	if _, err := identity.SyncGraph(ctx, db); err != nil {
		t.Fatal(err)
	}
	type detail struct {
		Accounts []identityAccount
		History  []identityLinkHistory
	}
	readDetail := func() detail {
		t.Helper()
		code, body := call(viewer, "GET", path, nil)
		var result detail
		if code != 200 || json.Unmarshal(body, &result) != nil {
			t.Fatalf("%d %s", code, body)
		}
		return result
	}
	d := readDetail()
	var manual *identityAccount
	for i := range d.Accounts {
		if d.Accounts[i].ID == alice1 {
			manual = &d.Accounts[i]
		}
	}
	if len(d.Accounts) != 2 || manual == nil || *manual.Basis != "manual" || manual.Logins == nil || manual.Logins.Success != 1 || len(manual.Logins.Sources) != 1 {
		t.Fatalf("合并后的账号或登录统计不对: %+v", d.Accounts)
	}

	if code, _ := call(analyst, "POST", path+"/rejections", map[string]any{"accountId": alice2}); code != http.StatusCreated {
		t.Fatalf("拒绝失败: %d", code)
	}
	c := candidates()
	if len(c) != 1 || c[0].RejectionID == nil {
		t.Fatalf("拒绝后候选应带拒绝记录: %+v", c)
	}
	if code, _ := call(analyst, "POST", path+"/links", map[string]any{"accountId": alice2}); code != http.StatusConflict {
		t.Fatalf("已拒绝的候选不能直接确认: %d", code)
	}
	if code, _ := call(analyst, "DELETE", "/api/identity-rejections/"+c[0].RejectionID.String(), nil); code != http.StatusNoContent {
		t.Fatalf("撤销拒绝失败: %d", code)
	}
	if c := candidates(); len(c) != 1 || c[0].RejectionID != nil {
		t.Fatalf("撤销拒绝后候选应恢复: %+v", c)
	}

	// 系统链接不能人工撤销；人工链接撤销后账号回到主机内身份
	var systemLink uuid.UUID
	if err := db.QueryRow(`SELECT id FROM identity_links WHERE account_id=$1 AND revoked_at IS NULL`, alice2).Scan(&systemLink); err != nil {
		t.Fatal(err)
	}
	if code, _ := call(analyst, "DELETE", "/api/identity-links/"+systemLink.String(), nil); code != http.StatusConflict {
		t.Fatalf("系统链接不应能撤销: %d", code)
	}
	if code, _ := call(viewer, "DELETE", "/api/identity-links/"+manual.LinkID.String(), nil); code != http.StatusForbidden {
		t.Fatalf("viewer 不能撤销: %d", code)
	}
	if code, _ := call(analyst, "DELETE", "/api/identity-links/"+manual.LinkID.String(), nil); code != http.StatusNoContent {
		t.Fatalf("撤销人工链接失败: %d", code)
	}
	var basis string
	if err := db.QueryRow(`SELECT basis FROM identity_links WHERE account_id=$1 AND revoked_at IS NULL`, alice1).Scan(&basis); err != nil || basis != "host_local" {
		t.Fatalf("撤销后未回到默认归属: %s %v", basis, err)
	}
	if d := readDetail(); len(d.Accounts) != 1 || len(d.History) != 1 || *d.History[0].RevokeReason != "manual_revoked" {
		t.Fatalf("撤销没有留痕: %+v", d.History)
	}

	// 资产账号视图：账号近期登录、身份跳转、未匹配登录
	code, body := call(viewer, "GET", "/api/assets/"+lin1.ID.String()+"/identity-accounts?hours=24", nil)
	var assetView struct {
		Accounts  []identityAccount
		Unmatched []unmatchedLogin
		Pending   int
	}
	if code != 200 || json.Unmarshal(body, &assetView) != nil {
		t.Fatalf("%d %s", code, body)
	}
	// 资产页列出这台主机全部账号（含系统账号），登录过的排前
	if len(assetView.Accounts) != 4 || *assetView.Accounts[0].Name != "alice" || assetView.Accounts[0].IdentityID == nil || assetView.Accounts[0].Logins.Success != 1 {
		t.Fatalf("资产账号视图不对: %s", body)
	}
	if len(assetView.Unmatched) != 1 || assetView.Unmatched[0].Name != "mallory" || assetView.Unmatched[0].State != "no_account" || assetView.Unmatched[0].Sources[0] != "198.51.100.9" {
		t.Fatalf("未匹配登录不对: %s", body)
	}
	if code, body := call(outsider, "GET", "/api/assets/"+lin1.ID.String()+"/identity-accounts", nil); code != 200 || !bytes.Contains(body, []byte(`"accounts":[]`)) {
		t.Fatalf("组外用户看到了资产账号: %s", body)
	}
}

// SID 同时对应两个 AD 来源的账号：不自动链接，两边都作为候选列出
func TestIdentityCandidatesSIDAmbiguous(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := identity.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	g := client.Group.Create().SetName("graph-sid").SaveX(ctx)
	win := client.Asset.Create().SetHostname("win").SetOs("windows").SetGroupID(g.ID).SaveX(ctx)
	const sid = "S-1-5-21-1004336348-1177238915-682003330-1105"
	for _, authority := range []string{"ldaps://dc1.example.invalid/DC=corp", "ldaps://dc2.example.invalid/DC=corp"} {
		source := directory.Source{ID: uuid.New(), GroupID: g.ID, Kind: "ad", Authority: authority}
		if err := directory.RegisterSource(ctx, db, source); err != nil {
			t.Fatal(err)
		}
		start := time.Now().UTC().Add(-time.Minute)
		if err := directory.SaveScan(ctx, db, directory.Scan{Source: source, StartedAt: start, FinishedAt: start, Accounts: []directory.Account{{ExternalID: "bob", Username: "bob", WindowsSID: sid}}}); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	event := uuid.New()
	if _, err := tx.Exec(`INSERT INTO events(id,ts,class_uid,source,asset_id,raw) VALUES($1,now(),3002,'agent',$2,$3::jsonb)`, event, win.ID,
		`{"event_id":4624,"log_name":"Security","activity_id":1,"status_id":1,"user":{"uid":"`+sid+`","name":"robert","domain":"CORP"}}`); err != nil {
		t.Fatal(err)
	}
	if err := identity.ObserveWindows(ctx, tx, event); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.SyncGraph(ctx, db); err != nil {
		t.Fatal(err)
	}
	var host uuid.UUID
	if err := db.QueryRow(`SELECT l.identity_id FROM identity_links l JOIN identity_accounts a ON a.id=l.account_id
 WHERE a.kind='windows' AND l.revoked_at IS NULL AND l.basis='host_local'`).Scan(&host); err != nil {
		t.Fatalf("歧义 SID 不应自动链接到目录身份: %v", err)
	}
	admin := client.User.Create().SetUsername("graph-admin").SetRole("admin").SetPasswordHash("unused").SaveX(ctx)
	w := httptest.NewRecorder()
	as(admin, Identities(db)).ServeHTTP(w, httptest.NewRequest("GET", "/api/identities/"+host.String()+"/candidates", nil))
	var result struct{ Items []identityCandidateRow }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || len(result.Items) != 2 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	for _, c := range result.Items {
		if c.Reason != "sid_ambiguous" || c.Direction != "outgoing" || c.ToKind != "directory" {
			t.Fatalf("候选不对: %+v", c)
		}
	}
}
