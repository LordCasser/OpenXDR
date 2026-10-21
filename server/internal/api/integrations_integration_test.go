//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openxdr/server/internal/auth"
	"openxdr/server/internal/testdb"
)

func TestIntegrationManagement(t *testing.T) {
	ctx, db := testdb.New(t)
	admin := db.User.Create().SetUsername("admin").SetPasswordHash("x").SetRole("admin").SaveX(ctx)
	viewer := db.User.Create().SetUsername("viewer").SetPasswordHash("x").SetRole("viewer").SaveX(ctx)
	g := db.Group.Create().SetName("ops").SaveX(ctx)
	h := Integrations(db)
	call := func(method, path string, body any, isAdmin bool) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, bytes.NewReader(b))
		u := admin
		if !isAdmin {
			u = viewer
		}
		r = r.WithContext(auth.WithUser(r.Context(), u))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := call("GET", "/api/system-integrations", nil, false); w.Code != 403 {
		t.Fatal("viewer 可管理集成")
	}
	body := integrationInput{Name: "cmdb", Purpose: "资产同步", OwnerID: admin.ID, Enabled: true, Scopes: []string{"assets:read"}, GroupIDs: []uuid.UUID{g.ID}}
	w := call("POST", "/api/system-integrations", body, true)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var row integrationRow
	if err := json.Unmarshal(w.Body.Bytes(), &row); err != nil {
		t.Fatal(err)
	}
	path := "/api/system-integrations/" + row.ID.String() + "/tokens"
	w = call("POST", path, map[string]any{"days": 90, "scopes": []string{"incidents:read"}}, true)
	if w.Code != 400 {
		t.Fatal("超范围 Token 被签发")
	}
	w = call("POST", path, map[string]any{"days": 90, "scopes": []string{"assets:read"}}, true)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var token integrationTokenRow
	if err := json.Unmarshal(w.Body.Bytes(), &token); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token.Token, "oxi_") || len(token.Token) < 40 {
		t.Fatal("Token 无效")
	}
	w = call("GET", path, nil, true)
	if bytes.Contains(w.Body.Bytes(), []byte(token.Token)) || bytes.Contains(w.Body.Bytes(), []byte("token_hash")) {
		t.Fatal("泄漏秘密")
	}
	w = call("DELETE", path+"/"+token.ID.String(), nil, true)
	if w.Code != 204 || !db.IntegrationToken.GetX(ctx, token.ID).Revoked {
		t.Fatal("吊销未落库")
	}
	body.Enabled = false
	w = call("PUT", "/api/system-integrations/"+row.ID.String(), body, true)
	if w.Code != 200 || db.Integration.GetX(ctx, row.ID).PermissionVersion != 2 {
		t.Fatal("修改权限未提升版本")
	}
}

func TestIntegrationOwnerAndGroupLifecycle(t *testing.T) {
	ctx, db := testdb.New(t)
	admin := db.User.Create().SetUsername("administrator").SetPasswordHash("x").SetRole("admin").SaveX(ctx)
	owner := db.User.Create().SetUsername("integration-owner").SetPasswordHash("x").SetRole("viewer").SaveX(ctx)
	g := db.Group.Create().SetName("linked").SaveX(ctx)
	i := db.Integration.Create().SetName("sync").SetPurpose("test").SetOwnerID(owner.ID).SetEnabled(true).SetScopes([]string{"assets:read"}).SaveX(ctx)
	db.IntegrationGroup.Create().SetIntegrationID(i.ID).SetGroupID(g.ID).SaveX(ctx)
	mux := http.NewServeMux()
	mapUsers(mux, db)
	mux.HandleFunc("DELETE /api/groups/{id}", deleteGroup(db, nil))
	call := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("DELETE", path, nil)
		r = r.WithContext(auth.WithUser(r.Context(), admin))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	if w := call("/api/users/" + owner.ID.String()); w.Code != 409 {
		t.Fatal("删除启用集成负责人未拒绝", w.Code, w.Body.String())
	}
	if w := call("/api/groups/" + g.ID.String()); w.Code != 204 {
		t.Fatal(w.Code, w.Body.String())
	}
	if db.IntegrationGroup.Query().CountX(ctx) != 0 || db.Integration.GetX(ctx, i.ID).PermissionVersion != 2 {
		t.Fatal("删除组未撤销授权")
	}
	db.Integration.UpdateOne(i).SetEnabled(false).ExecX(ctx)
	if w := call("/api/users/" + owner.ID.String()); w.Code != 204 {
		t.Fatal(w.Code, w.Body.String())
	}
}
