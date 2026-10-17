//go:build integration

package api

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/enroll"
	"openxdr/server/internal/hostimport"
	"openxdr/server/internal/testdb"
)

func TestHostImportAccessAndSecretBoundary(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("import").SaveX(ctx)
	g2 := db.Group.Create().SetName("other").SaveX(ctx)
	owner := db.User.Create().SetUsername("group-admin").SetPasswordHash("unused").SetRole("viewer").SaveX(ctx)
	viewer := db.User.Create().SetUsername("viewer").SetPasswordHash("unused").SetRole("viewer").SaveX(ctx)
	db.GroupMember.Create().SetGroupID(g.ID).SetUserID(owner.ID).SetRole("admin").ExecX(ctx)
	db.GroupMember.Create().SetGroupID(g.ID).SetUserID(viewer.ID).SetRole("viewer").ExecX(ctx)
	v, _ := hostimport.NewVault(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	h := HostImports(&hostimport.Service{DB: db, Vault: v}, &enroll.Service{}, "", false)
	send := func(u *ent.User, method, path string, body any) *httptest.ResponseRecorder {
		data, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, strings.NewReader(string(data)))
		if u != nil {
			r = r.WithContext(auth.WithUser(r.Context(), u))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if strings.Contains(w.Body.String(), "secret-marker") {
			t.Fatal("API 回显了密码")
		}
		return w
	}
	document := "hosts:\n - hostname: imported-01\n   address: 192.0.2.1\n   username: root\n   password: secret-marker\n"
	body := map[string]any{"groupId": g.ID, "document": document}
	for _, u := range []*ent.User{nil, viewer} {
		if w := send(u, "POST", "/api/host-import/preview", body); w.Code != 403 {
			t.Fatalf("未授权预览: %d", w.Code)
		}
	}
	body["groupId"] = g2.ID
	if w := send(owner, "POST", "/api/host-import/preview", body); w.Code != 403 {
		t.Fatalf("跨组预览: %d", w.Code)
	}
	body["groupId"] = g.ID
	if w := send(owner, "POST", "/api/host-import/preview", body); w.Code != 200 {
		t.Fatalf("组管理员预览: %d", w.Code)
	}
	if db.Asset.Query().CountX(ctx) != 0 {
		t.Fatal("预览产生了资产")
	}
	body["digest"] = "changed"
	if w := send(owner, "POST", "/api/host-import/commit", body); w.Code != 409 {
		t.Fatalf("未检查预览版本: %d", w.Code)
	}
	body["digest"] = hostimport.Digest(document)
	if w := send(owner, "POST", "/api/host-import/commit", body); w.Code != 201 {
		t.Fatalf("提交: %d %s", w.Code, w.Body.String())
	}
	c := db.HostCredential.Query().OnlyX(ctx)
	if w := send(owner, "GET", "/api/host-import/credentials?groupId="+g.ID.String(), nil); w.Code != 200 {
		t.Fatal("组管理员无法读取凭据元数据")
	}
	if w := send(viewer, "GET", "/api/host-import/credentials?groupId="+g.ID.String(), nil); w.Code != 403 {
		t.Fatal("viewer 读取了凭据元数据")
	}
	if w := send(owner, "POST", "/api/host-import/credentials/"+c.ID.String()+"/enroll", map[string]string{"fingerprint": "SHA256:test"}); w.Code != 503 {
		t.Fatal("关闭 SSH 纳管仍可连接")
	}
	// 解密失败也必须释放租约，不能因回调捕获被置空的指针而崩溃。
	db.HostCredential.UpdateOne(c).SetSealed([]byte("invalid")).ExecX(ctx)
	h = HostImports(&hostimport.Service{DB: db, Vault: v}, &enroll.Service{CA: &x509.Certificate{}, GRPCURL: "https://xdr.example.test:8081"}, "https://xdr.example.test", true)
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	if w := send(owner, "POST", "/api/host-import/credentials/"+c.ID.String()+"/enroll", map[string]string{"fingerprint": fingerprint}); w.Code != 409 {
		t.Fatal("解密失败未拒绝纳管")
	}
	if db.HostCredential.GetX(ctx, c.ID).LeaseUntil.After(time.Now()) {
		t.Fatal("解密失败未释放租约")
	}
	db.HostCredential.UpdateOne(c).SetSealed(c.Sealed).ExecX(ctx)
	if w := send(viewer, "DELETE", "/api/host-import/credentials/"+c.ID.String(), nil); w.Code != 403 {
		t.Fatal("viewer 删除了凭据")
	}
	if w := send(owner, "DELETE", "/api/host-import/credentials/"+c.ID.String(), nil); w.Code != http.StatusNoContent {
		t.Fatal("无法删除凭据")
	}
	if db.Asset.Query().CountX(ctx) != 1 {
		t.Fatal("删除凭据误删资产")
	}
	for _, entry := range db.AuditLog.Query().AllX(ctx) {
		raw, _ := json.Marshal(entry)
		if strings.Contains(string(raw), "secret-marker") {
			t.Fatal("审计包含密码")
		}
	}
}
