//go:build integration

package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/auth"
	"openxdr/server/internal/hostimport"
	"openxdr/server/internal/incidentstate"
	integrationapi "openxdr/server/internal/integration"
	"openxdr/server/internal/testdb"
)

func TestIntegrationSubscriptionLifecycle(t *testing.T) {
	ctx, db := testdb.New(t)
	admin := db.User.Create().SetUsername("admin").SetPasswordHash("x").SetRole("admin").SaveX(ctx)
	g := db.Group.Create().SetName("ops").SaveX(ctx)
	i := db.Integration.Create().SetName("tickets").SetPurpose("test").SetOwnerID(admin.ID).SetEnabled(true).SetScopes([]string{"incidents:read"}).SaveX(ctx)
	db.IntegrationGroup.Create().SetIntegrationID(i.ID).SetGroupID(g.ID).SaveX(ctx)
	vault, err := hostimport.NewVault(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("v", 32))))
	if err != nil {
		t.Fatal(err)
	}
	h := Integrations(db, vault, &integrationapi.OutboundAllow{DB: db})
	call := func(method, path string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		r = r.WithContext(auth.WithUser(r.Context(), admin))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	base := "/api/system-integrations/" + i.ID.String() + "/subscriptions"
	body := subscriptionInput{Name: "desk", URL: "https://desk.example.test/hook", GroupIDs: []string{g.ID.String()}, Kinds: []string{incidentstate.Created}, Enabled: true}
	w := call("POST", base, body)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var row subscriptionRow
	if err = json.Unmarshal(w.Body.Bytes(), &row); err != nil {
		t.Fatal(err)
	}
	if row.Secret == "" || row.KeyID == "" {
		t.Fatal("未返回签名秘密")
	}
	path := base + "/" + row.ID.String()
	if w = call("GET", base, nil); bytes.Contains(w.Body.Bytes(), []byte(row.Secret)) || bytes.Contains(w.Body.Bytes(), []byte("configurations")) {
		t.Fatal("读取泄漏密钥")
	}
	if w = call("POST", path+"/rotate", nil); w.Code != 409 {
		t.Fatal("未暂停即可轮换")
	}
	if w = call("POST", path+"/test", nil); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	d := db.IntegrationDelivery.Query().OnlyX(ctx)
	event := db.IntegrationEvent.GetX(ctx, d.EventID)
	if event.Kind != "integration.test" {
		t.Fatal("测试伪装真实事件")
	}
	body.URL = "https://new.example.test/hook"
	body.Enabled = false
	if w = call("PUT", path, body); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	snapshot := db.IntegrationSubscription.GetX(ctx, row.ID)
	if len(snapshot.Configurations) != 2 || snapshot.Configurations[0].URL != "https://desk.example.test/hook" || snapshot.Periods[0].To == nil {
		t.Fatal("历史版本或暂停区间丢失")
	}
	if db.IntegrationDelivery.GetX(ctx, d.ID).TargetURL != d.TargetURL {
		t.Fatal("旧积压自动改目标")
	}
	w = call("POST", path+"/rotate", nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var rotated subscriptionRow
	_ = json.Unmarshal(w.Body.Bytes(), &rotated)
	if rotated.Secret == row.Secret || rotated.KeyID == row.KeyID {
		t.Fatal("密钥未轮换")
	}
	if db.IntegrationDelivery.GetX(ctx, d.ID).KeyID != rotated.KeyID {
		t.Fatal("待发消息未切换新密钥")
	}
	db.IntegrationDelivery.UpdateOne(d).SetStatus("dead").SetAttempts(20).SetCompletedAt(time.Now()).ExecX(ctx)
	w = call("POST", "/api/system-integrations/"+i.ID.String()+"/deliveries/"+d.ID.String()+"/retry", nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	replay := db.IntegrationDelivery.GetX(ctx, d.ID)
	if replay.Status != "pending" || replay.EventID != d.EventID || replay.Attempts != 0 {
		t.Fatal("重放错误")
	}
	if w = call("DELETE", path, nil); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if db.IntegrationDelivery.GetX(ctx, d.ID).Status != "cancelled_scope" {
		t.Fatal("删除订阅没有取消积压")
	}
	list := "/api/system-integrations/" + i.ID.String() + "/deliveries"
	w = call("GET", list+"?status=cancelled_scope&limit=1", nil)
	var page struct {
		Total   int           `json:"total"`
		Items   []deliveryRow `json:"items"`
		Summary struct {
			Counts map[string]int `json:"counts"`
		} `json:"summary"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.Total != 1 || len(page.Items) != 1 || page.Summary.Counts["cancelled_scope"] != 1 {
		t.Fatal("投递筛选或统计错误", w.Code, w.Body.String())
	}
	for _, filter := range []string{"?from=invalid", "?offset=-1", "?limit=201", "?status=unknown"} {
		if w = call("GET", list+filter, nil); w.Code != 400 {
			t.Fatal("接受无效筛选", filter, w.Code)
		}
	}

}
