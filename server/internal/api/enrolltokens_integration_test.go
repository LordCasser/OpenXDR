//go:build integration

package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"openxdr/server/ent"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/enroll"
	"openxdr/server/internal/testdb"
)

// 组 admin 能签本组 agent 令牌，签不了流量探针令牌；探针令牌只有全局 admin 能签。
func TestEnrollTokenKinds(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("edge").SaveX(ctx)
	groupAdmin := db.User.Create().SetUsername("group-admin").SetPasswordHash("unused").SetRole("viewer").SaveX(ctx)
	db.GroupMember.Create().SetGroupID(g.ID).SetUserID(groupAdmin.ID).SetRole("admin").ExecX(ctx)
	admin := db.User.Create().SetUsername("root").SetPasswordHash("unused").SetRole("admin").SaveX(ctx)
	h := EnrollTokens(db, &enroll.Service{DB: db}, enroll.NewDists(""))
	issue := func(u *ent.User, kind string) *httptest.ResponseRecorder {
		data, _ := json.Marshal(map[string]any{"groupId": g.ID, "days": 1, "kind": kind})
		r := httptest.NewRequest("POST", "/api/enroll-tokens", strings.NewReader(string(data)))
		r = r.WithContext(auth.WithUser(r.Context(), u))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := issue(groupAdmin, ""); w.Code != 201 || !strings.Contains(w.Body.String(), `"kind":"agent"`) {
		t.Fatalf("组 admin 应能签 agent 令牌：%d %s", w.Code, w.Body.String())
	}
	if w := issue(groupAdmin, "sensor"); w.Code != 403 {
		t.Fatalf("组 admin 不应能签探针令牌：%d", w.Code)
	}
	if w := issue(admin, "sensor"); w.Code != 201 || !strings.Contains(w.Body.String(), `"kind":"sensor"`) {
		t.Fatalf("全局 admin 应能签探针令牌：%d %s", w.Code, w.Body.String())
	}
	if w := issue(admin, "root"); w.Code != 400 {
		t.Fatalf("未知用途应拒绝：%d", w.Code)
	}
}
