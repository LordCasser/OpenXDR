//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/testdb"
)

func TestTicketWritebackIdempotencyAndRevision(t *testing.T) {
	ctx, db := testdb.New(t)
	owner := db.User.Create().SetUsername("owner").SetPasswordHash("x").SetRole("admin").SaveX(ctx)
	g := db.Group.Create().SetName("A").SaveX(ctx)
	a := db.Asset.Create().SetHostname("host").SetGroupID(g.ID).SaveX(ctx)
	inc := db.Incident.Create().SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	ev := db.Event.Create().SetTs(time.Now()).SetClassUID(1007).SetSource("agent").SetAssetID(a.ID).SetRaw(json.RawMessage(`{}`)).SaveX(ctx)
	db.Alert.Create().SetTs(time.Now()).SetSeverity(3).SetRuleID("rule").SetEventID(ev.ID).SetAssetID(a.ID).SetIncidentID(inc.ID).SaveX(ctx)
	i := db.Integration.Create().SetName("tickets").SetPurpose("test").SetOwnerID(owner.ID).SetEnabled(true).SetScopes(AllowedScopes).SetResolutionEnabled(true).SetAllowedResolutions([]string{"closed", "false_positive"}).SaveX(ctx)
	db.IntegrationGroup.Create().SetIntegrationID(i.ID).SetGroupID(g.ID).SaveX(ctx)
	plain := "oxi_" + strings.Repeat("x", 43)
	db.IntegrationToken.Create().SetIntegrationID(i.ID).SetPrefix("oxi_xxx").SetTokenHash(TokenHash(plain)).SetScopes(AllowedScopes).SetExpiresAt(time.Now().Add(time.Hour)).SaveX(ctx)
	service := &Service{DB: db, Enabled: true, CursorKey: []byte(strings.Repeat("s", 32))}
	h := service.Handler()
	call := func(method, path, key string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+plain)
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	base := "/api/integration/v1/incidents/" + inc.ID.String()
	ticket := ticketInput{URL: "https://tickets.example.test/123", Status: "open", Title: "处置"}
	w := call("PUT", base+"/tickets/SEC-123", "create", ticket)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	repeat := call("PUT", base+"/tickets/SEC-123", "create", ticket)
	if repeat.Code != 201 || !sameJSON(repeat.Body.Bytes(), w.Body.Bytes()) || db.ExternalTicket.Query().CountX(ctx) != 1 {
		t.Fatal("重复请求未复用结果")
	}
	ticket.Title = "另一个请求"
	if w = call("PUT", base+"/tickets/SEC-123", "create", ticket); w.Code != 409 {
		t.Fatal("同键不同内容未拒绝", w.Code)
	}
	revision := int64(0)
	request := resolutionInput{ExternalID: "SEC-123", ExpectedRevision: &revision, Status: "closed", Note: "已修复", Operator: "claimed-user"}
	w = call("POST", base+"/resolution", "resolve", request)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	row := db.Incident.GetX(ctx, inc.ID)
	if row.Status != "closed" || row.IntegrationRevision != 1 || row.ResolutionSource == nil || *row.ResolutionSource != "external_integration" || *row.ResolvedBy != "integration:"+i.ID.String() {
		t.Fatal("回写来源或版本错误")
	}
	repeated := call("POST", base+"/resolution", "resolve", request)
	if repeated.Code != 200 || !sameJSON(repeated.Body.Bytes(), w.Body.Bytes()) || db.IntegrationEvent.Query().CountX(ctx) != 1 {
		t.Fatal("重复回写再次执行")
	}
	if w = call("POST", base+"/resolution", "stale", request); w.Code != 409 {
		t.Fatal("旧版本被覆盖", w.Code, w.Body.String())
	}
	revision = 1
	request.Status = "open"
	if w = call("POST", base+"/resolution", "reopen", request); w.Code != 403 {
		t.Fatal("越权重开", w.Code)
	}
	db.Incident.UpdateOneID(inc.ID).SetAiVerdict(json.RawMessage(`{"verdict":"malicious"}`)).ExecX(ctx)
	request.Status = "false_positive"
	if w = call("POST", base+"/resolution", "malicious", request); w.Code != 403 {
		t.Fatal("恶意误报缺确认仍关闭", w.Code)
	}
	db.Asset.UpdateOne(a).ClearGroupID().ExecX(ctx)
	if w = call("POST", base+"/resolution", "resolve", request); w.Code != 404 {
		t.Fatal("权限撤销后仍可复用幂等结果", w.Code)
	}
	// 范围外与不存在的 incident 应答一致，不能借此探测别组事件
	message := func(w *httptest.ResponseRecorder) string {
		var body struct {
			Error struct{ Code, Message string }
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return body.Error.Code + "|" + body.Error.Message
	}
	h = (&Service{DB: db, Enabled: true, CursorKey: []byte(strings.Repeat("s", 32))}).Handler() // 换实例重置写限流
	hidden := call("PUT", base+"/tickets/SEC-9", "probe-hidden", ticket)
	missing := call("PUT", "/api/integration/v1/incidents/"+uuid.NewString()+"/tickets/SEC-9", "probe-missing", ticket)
	if hidden.Code != 404 || missing.Code != 404 || message(hidden) != message(missing) {
		t.Fatalf("范围外与不存在应答不同: %d %s / %d %s", hidden.Code, message(hidden), missing.Code, message(missing))
	}
}

func sameJSON(a, b []byte) bool {
	var x, y any
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && reflect.DeepEqual(x, y)
}
