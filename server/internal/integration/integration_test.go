//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
)

func TestIntegrationReadBoundary(t *testing.T) {
	ctx, db := testdb.New(t)
	owner := db.User.Create().SetUsername("owner").SetPasswordHash("x").SetRole("admin").SaveX(ctx)
	ga := db.Group.Create().SetName("A").SaveX(ctx)
	gb := db.Group.Create().SetName("B").SaveX(ctx)
	a := db.Asset.Create().SetHostname("visible").SetGroupID(ga.ID).SaveX(ctx)
	db.Asset.Create().SetHostname("visible2").SetGroupID(ga.ID).SaveX(ctx)
	hidden := db.Asset.Create().SetHostname("hidden").SetGroupID(gb.ID).SaveX(ctx)
	db.Asset.Create().SetHostname("ungrouped").SaveX(ctx)
	inc := db.Incident.Create().SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	cross := db.Incident.Create().SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	for _, pair := range []struct {
		i *ent.Incident
		a *ent.Asset
	}{{inc, a}, {cross, a}, {cross, hidden}} {
		event := db.Event.Create().SetTs(time.Now()).SetClassUID(1007).SetSource("agent").SetAssetID(pair.a.ID).SetRaw(json.RawMessage(`{}`)).SaveX(ctx)
		db.Alert.Create().SetTs(time.Now()).SetSeverity(3).SetRuleID("test").SetEventID(event.ID).SetAssetID(pair.a.ID).SetIncidentID(pair.i.ID).SaveX(ctx)
	}
	i := db.Integration.Create().SetName("CMDB").SetPurpose("test").SetOwnerID(owner.ID).SetEnabled(true).SetScopes(ReadScopes).SaveX(ctx)
	db.IntegrationGroup.Create().SetIntegrationID(i.ID).SetGroupID(ga.ID).SaveX(ctx)
	plain := "oxi_" + strings.Repeat("x", 43)
	token := db.IntegrationToken.Create().SetIntegrationID(i.ID).SetPrefix("oxi_xxx").SetTokenHash(TokenHash(plain)).SetScopes(ReadScopes).SetExpiresAt(time.Now().Add(time.Hour)).SaveX(ctx)
	s := &Service{DB: db, CursorKey: []byte(strings.Repeat("s", 32))}
	h := s.Handler()
	call := func(path, auth string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("GET", path, nil)
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct {
		path, token string
		code        int
	}{
		{"/api/integration/v1/assets", plain, 200}, {"/api/integration/v1/assets", "", 401},
		{"/api/integration/v1/assets/" + hidden.ID.String(), plain, 404},
		{"/api/integration/v1/incidents/" + cross.ID.String(), plain, 404},
		{"/api/integration/v1/incidents/" + inc.ID.String(), plain, 200},
		{"/api/integration/v1/assets?limit=501", plain, 400},
		{"/api/integration/v1/assets?foo=bar", plain, 400},
	} {
		w := call(tc.path, tc.token)
		if w.Code != tc.code {
			t.Fatalf("%s: %d %s", tc.path, w.Code, w.Body.String())
		}
	}
	w := call("/api/integration/v1/assets?limit=1", plain)
	var page struct {
		Items      []assetRow `json:"items"`
		NextCursor string     `json:"nextCursor"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("分页错误 %s %v", w.Body.String(), err)
	}
	next := call("/api/integration/v1/assets?limit=1&cursor="+page.NextCursor, plain)
	if next.Code != 200 {
		t.Fatal(next.Body.String())
	}
	db.Integration.UpdateOne(i).AddPermissionVersion(1).ExecX(ctx)
	if w = call("/api/integration/v1/assets?limit=1&cursor="+page.NextCursor, plain); w.Code != 400 {
		t.Fatal("旧权限游标未失效")
	}
	db.IntegrationToken.UpdateOne(token).SetScopes([]string{"assets:read"}).ExecX(ctx)
	if w = call("/api/integration/v1/incidents", plain); w.Code != 403 {
		t.Fatal("Token scope 未限制权限")
	}
	db.Integration.UpdateOne(i).SetEnabled(false).ExecX(ctx)
	if w = call("/api/integration/v1/assets", plain); w.Code != 401 {
		t.Fatal("停用身份未拒绝")
	}
	db.Integration.UpdateOne(i).SetEnabled(true).ExecX(ctx)
	db.IntegrationGroup.Delete().ExecX(ctx)
	if w = call("/api/integration/v1/assets", plain); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"items":[]`)) {
		t.Fatal("空授权组可见资产", w.Body.String())
	}
	db.IntegrationToken.UpdateOne(token).SetExpiresAt(time.Now().Add(-time.Minute)).ExecX(ctx)
	if w = call("/api/integration/v1/assets", plain); w.Code != 401 {
		t.Fatal("过期令牌未拒绝")
	}
	db.IntegrationToken.UpdateOne(token).SetExpiresAt(time.Now().Add(time.Hour)).ExecX(ctx)
	db.IntegrationToken.UpdateOne(token).SetRevoked(true).ExecX(ctx)
	if w = call("/api/integration/v1/assets", plain); w.Code != 401 {
		t.Fatal("吊销无效")
	}
}
