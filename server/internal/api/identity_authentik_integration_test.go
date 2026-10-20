//go:build integration

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/identity"
	"openxdr/server/internal/identity/directory"
	"openxdr/server/internal/testdb"
)

// Authentik 走生产配置、同步、身份图与查询接口全链路：目录账号是锚点，同名端点账号只作候选
func TestAuthentikDirectoryEndToEnd(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := identity.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	g := client.Group.Create().SetName("authentik").SaveX(ctx)
	lin := client.Asset.Create().SetHostname("lin-ak").SetOs("linux").SetGroupID(g.ID).SaveX(ctx)
	viewer := client.User.Create().SetUsername("ak-viewer").SetRole("viewer").SetPasswordHash("unused").SaveX(ctx)
	client.GroupMember.Create().SetUserID(viewer.ID).SetGroupID(g.ID).SetRole("viewer").SaveX(ctx)

	const alice = "0f8fad5b-d9cb-469f-a165-70867728950e"
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v3/core/users/" || r.Header.Get("Authorization") != "Bearer ak-token" {
			http.Error(w, "bad", 400)
			return
		}
		users := []string{
			`{"pk":7,"uuid":"` + alice + `","username":"alice","name":"Alice","email":"alice@example.invalid","is_active":true,"type":"internal"}`,
			`{"pk":8,"uuid":"1b4e28ba-2fa1-41d2-883f-0016d3cca427","username":"ak-outpost-1","name":"Outpost","email":"","is_active":true,"type":"internal_service_account"}`,
		}
		if r.URL.Query().Get("page_size") == "1" {
			users = users[:1]
		}
		fmt.Fprintf(w, `{"pagination":{"next":0,"previous":0,"count":2,"current":1,"total_pages":1,"start_index":1,"end_index":2},"results":[%s]}`, strings.Join(users, ","))
	}))
	defer s.Close()
	root := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}))
	raw := fmt.Sprintf(`[{"id":%q,"groupId":%q,"kind":"authentik","url":%q,"tokenEnv":"AUTHENTIK_TOKEN","caEnv":"AUTHENTIK_CA"}]`, uuid.NewString(), g.ID, s.URL)
	jobs, err := directory.LoadConfig(raw, func(key string) string {
		return map[string]string{"AUTHENTIK_TOKEN": "ak-token", "AUTHENTIK_CA": root}[key]
	})
	if err != nil {
		t.Fatal(err)
	}
	source := jobs[0].Source
	if err := directory.RegisterSource(ctx, db, source); err != nil {
		t.Fatal(err)
	}
	run, err := directory.SyncOnce(ctx, db, source, jobs[0].Reader)
	if err != nil || run.Status != "succeeded" || run.AccountCount != 1 {
		t.Fatalf("同步失败或服务账号未过滤: %+v %v", run, err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	event := uuid.New()
	passwd := `{"activity_id":2,"device":{"local_accounts":{"version":1,"source":"etc-passwd","state":"observed","items":[{"name":"alice","uid":1000,"gid":1000,"shell":"/bin/sh"}]}}}`
	if _, err := tx.Exec(`INSERT INTO events(id,ts,class_uid,source,asset_id,raw) VALUES($1,$2,5001,'agent',$3,$4::jsonb)`, event, time.Now().UTC().Add(-time.Hour), lin.ID, passwd); err != nil {
		t.Fatal(err)
	}
	if err := identity.ObserveLinuxAccounts(ctx, tx, event); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.SyncGraph(ctx, db); err != nil {
		t.Fatal(err)
	}

	get := func(h http.Handler, path string, out any) {
		t.Helper()
		w := httptest.NewRecorder()
		as(viewer, h).ServeHTTP(w, httptest.NewRequest("GET", path, nil).WithContext(context.Background()))
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), out) != nil {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	var sources struct{ Items []directorySource }
	get(IdentityDirectories(db), "/api/identity-directories?groupId="+g.ID.String(), &sources)
	if len(sources.Items) != 1 || sources.Items[0].Kind != "authentik" || sources.Items[0].Authority != s.URL ||
		sources.Items[0].LatestStatus == nil || *sources.Items[0].LatestStatus != "succeeded" || sources.Items[0].LastFinishedAt == nil {
		t.Fatalf("目录状态不对: %+v", sources.Items)
	}
	var accounts struct{ Items []directoryAccount }
	get(IdentityDirectories(db), "/api/identity-directories/"+source.ID.String()+"/accounts", &accounts)
	if len(accounts.Items) != 1 || accounts.Items[0].ExternalID != alice || accounts.Items[0].Username != "alice" || accounts.Items[0].WindowsSID != nil {
		t.Fatalf("目录账号不对: %+v", accounts.Items)
	}

	var identities struct{ Items []identitySummary }
	get(Identities(db), "/api/identities?groupId="+g.ID.String()+"&kind=directory", &identities)
	if len(identities.Items) != 1 || identities.Items[0].AnchorKind != "directory" {
		t.Fatalf("Authentik 账号应成为目录身份锚点: %+v", identities.Items)
	}
	var basis string
	if err := db.QueryRow(`SELECT l.basis FROM identity_links l JOIN identity_accounts a ON a.id=l.account_id AND l.revoked_at IS NULL WHERE a.kind='linux' AND a.name='alice'`).Scan(&basis); err != nil || basis != "host_local" {
		t.Fatalf("同名端点账号不得自动链接到 Authentik 身份: %s %v", basis, err)
	}
	var candidates struct{ Items []identityCandidateRow }
	get(Identities(db), "/api/identities/"+identities.Items[0].ID.String()+"/candidates", &candidates)
	if len(candidates.Items) != 1 || candidates.Items[0].Reason != "same_name" || candidates.Items[0].Direction != "incoming" {
		t.Fatalf("同名端点账号应作为候选: %+v", candidates.Items)
	}
}
