//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"openxdr/server/ent"
	"openxdr/server/ent/auditlog"
	"openxdr/server/ent/decoydeployment"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/testdb"
)

func TestSSHDecoyRegistration(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("A").SaveX(ctx)
	other := db.Group.Create().SetName("B").SaveX(ctx)
	host := db.Asset.Create().SetHostname("decoy-host").SetGroupID(g.ID).SaveX(ctx)
	admin := &ent.User{Username: "root", Role: "admin"}
	owner := db.User.Create().SetUsername("owner").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	viewer := db.User.Create().SetUsername("viewer").SetPasswordHash("x").SetRole("viewer").SaveX(ctx)
	db.GroupMember.Create().SetUserID(owner.ID).SetGroupID(g.ID).SetRole("admin").ExecX(ctx)
	db.GroupMember.Create().SetUserID(viewer.ID).SetGroupID(g.ID).SetRole("viewer").ExecX(ctx)
	mux := http.NewServeMux()
	mapSSHDecoys(mux, db)
	request := func(u *ent.User, method, path string, body any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, bytes.NewReader(b))
		if u != nil {
			r = r.WithContext(auth.WithUser(r.Context(), u))
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	input := map[string]any{"assetId": host.ID, "profile": "decoy", "port": 2222}
	for _, u := range []*ent.User{nil, viewer} {
		w := request(u, "POST", "/api/ssh-decoys", input)
		if w.Code != 401 && w.Code != 403 {
			t.Fatalf("权限检查: %d %s", w.Code, w.Body)
		}
	}
	invalid := map[string]any{"assetId": host.ID, "profile": "decoy", "port": 2222, "template": "custom"}
	if w := request(owner, "POST", "/api/ssh-decoys", invalid); w.Code != 400 {
		t.Fatalf("自定义模板未拒绝: %d", w.Code)
	}
	w := request(owner, "POST", "/api/ssh-decoys", input)
	if w.Code != 201 {
		t.Fatalf("创建: %d %s", w.Code, w.Body)
	}
	var row ent.DecoyDeployment
	if err := json.Unmarshal(w.Body.Bytes(), &row); err != nil {
		t.Fatal(err)
	}
	if row.Status != decoydeployment.StatusRegistered || row.Template != "identify-v1" {
		t.Fatalf("登记伪造运行状态或模板: %+v", row)
	}
	if w := request(owner, "POST", "/api/ssh-decoys", input); w.Code != 409 {
		t.Fatalf("重复端口: %d %s", w.Code, w.Body)
	}
	listPath := "/api/ssh-decoys?groupId=" + g.ID.String()
	if w := request(viewer, "GET", listPath, nil); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(row.ID.String())) {
		t.Fatalf("组内读取: %d %s", w.Code, w.Body)
	}
	if w := request(owner, "GET", "/api/ssh-decoys?groupId="+other.ID.String(), nil); w.Code != 403 {
		t.Fatalf("跨组读取: %d", w.Code)
	}
	db.Asset.UpdateOne(host).SetGroupID(other.ID).ExecX(ctx)
	if w := request(owner, "GET", listPath, nil); w.Code != 200 || bytes.Contains(w.Body.Bytes(), []byte(row.ID.String())) {
		t.Fatalf("迁组后泄漏: %d %s", w.Code, w.Body)
	}
	revokePath := "/api/ssh-decoys/" + row.ID.String() + "/revoke"
	if w := request(owner, "POST", revokePath, nil); w.Code != 403 {
		t.Fatalf("迁组后越权撤销: %d", w.Code)
	}
	for range 2 {
		if w := request(admin, "POST", revokePath, nil); w.Code != 204 {
			t.Fatalf("撤销: %d %s", w.Code, w.Body)
		}
	}
	if n := db.AuditLog.Query().Where(auditlog.TargetEQ(row.ID.String())).CountX(ctx); n != 2 {
		t.Fatalf("创建/撤销审计数 %d", n)
	}
	revoked := db.DecoyDeployment.GetX(ctx, row.ID)
	if revoked.Status != decoydeployment.StatusRevoked || revoked.RevokedAt == nil || revoked.RevokedBy == nil {
		t.Fatalf("撤销记录不完整: %+v", revoked)
	}
	// 并发登记仍只有一个赢家；已撤销的旧登记不占端口。
	codes := make(chan int, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() { codes <- request(admin, "POST", "/api/ssh-decoys", input).Code })
	}
	wg.Wait()
	close(codes)
	counts := map[int]int{}
	for code := range codes {
		counts[code]++
	}
	if counts[201] != 1 || counts[409] != 1 {
		t.Fatalf("并发登记: %v", counts)
	}
	if n := db.DecoyDeployment.Query().Where(decoydeployment.StatusEQ(decoydeployment.StatusRegistered)).CountX(ctx); n != 1 {
		t.Fatalf("未撤销登记数 %d", n)
	}
}

func TestSSHDecoyAuditRollbackAndPagination(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("audit").SaveX(ctx)
	host := db.Asset.Create().SetHostname("host").SetGroupID(g.ID).SaveX(ctx)
	mux := http.NewServeMux()
	mapSSHDecoys(mux, db)
	request := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r = r.WithContext(auth.WithUser(r.Context(), &ent.User{Username: "admin", Role: "admin"}))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	failAudit := true
	db.AuditLog.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			if failAudit {
				return nil, errors.New("测试审计失败")
			}
			return next.Mutate(ctx, m)
		})
	})
	body := fmt.Sprintf(`{"assetId":%q,"profile":"pause","port":2222}`, host.ID.String())
	if w := request("POST", "/api/ssh-decoys", body); w.Code != 500 {
		t.Fatalf("审计失败响应: %d", w.Code)
	}
	if n := db.DecoyDeployment.Query().CountX(ctx); n != 0 {
		t.Fatalf("审计失败未回滚登记: %d", n)
	}
	failAudit = false
	if w := request("POST", "/api/ssh-decoys", body); w.Code != 201 {
		t.Fatalf("登记: %d %s", w.Code, w.Body)
	}
	row := db.DecoyDeployment.Query().OnlyX(ctx)
	failAudit = true
	if w := request("POST", "/api/ssh-decoys/"+row.ID.String()+"/revoke", ""); w.Code != 500 {
		t.Fatalf("撤销审计失败响应: %d", w.Code)
	}
	if db.DecoyDeployment.GetX(ctx, row.ID).Status != decoydeployment.StatusRegistered {
		t.Fatal("审计失败未回滚撤销")
	}
	for port := 3000; port < 3050; port++ {
		db.DecoyDeployment.Create().SetAssetID(host.ID).SetProfile("padding").SetTemplate("padding-8k-v1").SetPort(port).SetCreatedBy("admin").ExecX(ctx)
	}
	var first, second struct {
		Items []*ent.DecoyDeployment `json:"items"`
		More  bool                   `json:"more"`
	}
	path := "/api/ssh-decoys?groupId=" + g.ID.String()
	w := request("GET", path, "")
	if w.Code != 200 {
		t.Fatalf("列表: %d %s", w.Code, w.Body)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	w = request("GET", path+"&offset=50", "")
	if err := json.Unmarshal(w.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 50 || !first.More || len(second.Items) != 1 || second.More {
		t.Fatalf("分页: %d/%t %d/%t", len(first.Items), first.More, len(second.Items), second.More)
	}
	for _, item := range first.Items {
		if item.ID == second.Items[0].ID {
			t.Fatal("分页重复")
		}
	}
}
