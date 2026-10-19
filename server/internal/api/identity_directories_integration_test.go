//go:build integration

package api

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/identity/directory"
	"openxdr/server/internal/testdb"
)

func TestIdentityDirectoryAccessAndPagination(t *testing.T) {
	ctx, c := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := directory.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	a := c.Group.Create().SetName("directory-a").SaveX(ctx)
	b := c.Group.Create().SetName("directory-b").SaveX(ctx)
	u := c.User.Create().SetUsername("directory-viewer").SetPasswordHash("unused").SetRole("viewer").SaveX(ctx)
	admin := c.User.Create().SetUsername("directory-admin").SetPasswordHash("unused").SetRole("admin").SaveX(ctx)
	m := c.GroupMember.Create().SetUserID(u.ID).SetGroupID(a.ID).SetRole("viewer").SaveX(ctx)
	source := directory.Source{ID: uuid.New(), GroupID: a.ID, Kind: "keycloak", Authority: "https://directory.invalid/realms/one"}
	other := source
	other.ID = uuid.New()
	other.GroupID = b.ID
	for _, s := range []directory.Source{source, other} {
		if err := directory.RegisterSource(ctx, db, s); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now().UTC().Add(-time.Hour)
	on := true
	if err := directory.SaveScan(ctx, db, directory.Scan{Source: source, StartedAt: start, FinishedAt: start.Add(time.Minute), Accounts: []directory.Account{{ExternalID: "one", Username: "one", Enabled: &on}, {ExternalID: "two", Username: "two"}}}); err != nil {
		t.Fatal(err)
	}
	runID := uuid.New()
	if _, err := db.ExecContext(ctx, `INSERT INTO identity_directory_runs(id,source_id,status,error_code,started_at,finished_at) VALUES($1,$2,'failed','read_failed',now(),now())`, runID, source.ID); err != nil {
		t.Fatal(err)
	}
	h := IdentityDirectories(db)
	get := func(user *ent.User, path string) []byte {
		t.Helper()
		w := httptest.NewRecorder()
		as(user, h).ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		return w.Body.Bytes()
	}
	sourcesPath := "/api/identity-directories?groupId=" + a.ID.String()
	base := "/api/identity-directories/" + source.ID.String()
	var sources struct {
		Items []directorySource `json:"items"`
	}
	if err := json.Unmarshal(get(u, sourcesPath), &sources); err != nil {
		t.Fatal(err)
	}
	if len(sources.Items) != 1 || sources.Items[0].LatestStatus == nil || *sources.Items[0].LatestStatus != "failed" || sources.Items[0].LastFinishedAt == nil {
		t.Fatal("最近失败丢失或覆盖最后成功时间")
	}
	if err := json.Unmarshal(get(admin, "/api/identity-directories?groupId="+b.ID.String()), &sources); err != nil {
		t.Fatal(err)
	}
	if len(sources.Items) != 1 || sources.Items[0].LatestStatus != nil || sources.Items[0].LastFinishedAt != nil {
		t.Fatal("从未同步被伪造为成功")
	}
	var page struct {
		Items     []directoryAccount `json:"items"`
		Truncated bool               `json:"truncated"`
		Next      *uuid.UUID         `json:"next"`
	}
	if err := json.Unmarshal(get(u, base+"/accounts?limit=1"), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || !page.Truncated || page.Next == nil {
		t.Fatal("首屏游标错误")
	}
	first := page.Items[0]
	next := page.Next.String()
	if err := json.Unmarshal(get(u, base+"/accounts?limit=1&after="+next), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Truncated || page.Next != nil || page.Items[0].ID == first.ID {
		t.Fatal("末屏游标错误")
	}
	if first.Enabled != nil && page.Items[0].Enabled != nil {
		t.Fatal("未知状态被补造")
	}
	var runs struct {
		Items []directory.Run `json:"items"`
	}
	if err := json.Unmarshal(get(u, base+"/runs"), &runs); err != nil || len(runs.Items) != 1 || runs.Items[0].ID != runID {
		t.Fatal("运行记录错误")
	}
	checkEmpty := func(user *ent.User, path string) {
		t.Helper()
		var out struct {
			Items []json.RawMessage `json:"items"`
		}
		if err := json.Unmarshal(get(user, path), &out); err != nil || out.Items == nil || len(out.Items) != 0 {
			t.Fatalf("越权或空列表格式错误: %s", path)
		}
	}
	checkEmpty(u, "/api/identity-directories?groupId="+b.ID.String())
	checkEmpty(u, "/api/identity-directories/"+other.ID.String()+"/accounts")
	c.GroupMember.DeleteOne(m).ExecX(ctx)
	for _, path := range []string{sourcesPath, base + "/accounts", base + "/runs"} {
		checkEmpty(u, path)
	}
	// 请求上下文仍是旧管理员对象，数据库已降权。
	c.User.UpdateOne(admin).SetRole("viewer").ExecX(ctx)
	for _, path := range []string{sourcesPath, base + "/accounts", base + "/runs"} {
		checkEmpty(admin, path)
	}
	for _, path := range []string{"/api/identity-directories", sourcesPath + "&limit=0", base + "/runs?limit=201", base + "/accounts?after=bad", "/api/identity-directories/bad/accounts"} {
		w := httptest.NewRecorder()
		as(u, h).ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 400 {
			t.Fatalf("错误参数获准: %s", path)
		}
	}
	for _, path := range []string{sourcesPath, base + "/accounts", base + "/runs"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 401 {
			t.Fatal("未登录获准")
		}
	}
}
