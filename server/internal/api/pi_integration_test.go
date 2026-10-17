//go:build integration

package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"openxdr/server/ent"
	"openxdr/server/internal/agentchat"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/piruntime"
	"openxdr/server/internal/response"
	"openxdr/server/internal/testdb"
	"strings"
	"testing"
	"time"
)

func TestPiGroupAPI(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("allowed").SaveX(ctx)
	other := db.Group.Create().SetName("other").SaveX(ctx)
	user := db.User.Create().SetUsername("member").SetPasswordHash("unused").SetRole("viewer").SaveX(ctx)
	member := db.GroupMember.Create().SetUserID(user.ID).SetGroupID(group.ID).SetRole("admin").SaveX(ctx)
	token := uuid.NewString()
	sum := sha256.Sum256([]byte(token))
	db.Session.Create().SetUserID(user.ID).SetTokenHash(hex.EncodeToString(sum[:])).SetExpiresAt(time.Now().Add(time.Hour)).SaveX(ctx)
	mux := http.NewServeMux()
	gate := &commandgate.Gate{DB: db}
	mapAgentSessions(mux, db, &agentchat.Service{DB: db, Model: "test", Runtime: apiPiRunner{}})
	mapCommandPolicy(mux, db, gate)
	mapCommands(mux, db, response.NewHub(db, false), nil, gate)
	handler := auth.Middleware(db, mux)
	request := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/api/agent-sessions", "/api/agent-reports", "/api/command-policies", "/api/approvals"} {
		w := request("GET", path+"?groupId="+other.ID.String(), "")
		if w.Code != 403 {
			t.Fatalf("跨组 %s: %d %s", path, w.Code, w.Body.String())
		}
	}
	w := request("POST", "/api/agent-sessions", `{"groupId":"`+group.ID.String()+`"}`)
	if w.Code != 201 {
		t.Fatalf("组 admin 创建会话: %d %s", w.Code, w.Body.String())
	}
	var session ent.AgentSession
	if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}

	// 交给 AI：绑定对象必须都属于本组，格式不对或跨组都拒绝
	mine := db.Asset.Create().SetHostname("h1").SetGroupID(group.ID).SaveX(ctx)
	theirs := db.Asset.Create().SetHostname("h2").SetGroupID(other.ID).SaveX(ctx)
	incOf := func(asset uuid.UUID) uuid.UUID {
		inc := db.Incident.Create().SetStatus("triaged").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
		db.Alert.Create().SetTs(time.Now()).SetRuleID("r").SetSeverity(3).SetAssetID(asset).SetIncidentID(inc.ID).SaveX(ctx)
		return inc.ID
	}
	myInc, theirInc := incOf(mine.ID), incOf(theirs.ID)
	myFinding := db.Finding.Create().SetGroupID(group.ID).SetAssetID(mine.ID).SetKey("k").SetTitle("t").SaveX(ctx)
	for body, want := range map[string]int{
		`"incident:` + theirInc.String() + `"`:                                      400,
		`"bogus:` + myInc.String() + `"`:                                            400,
		`"incident:` + myInc.String() + `","finding:` + myFinding.ID.String() + `"`: 201,
	} {
		w := request("POST", "/api/agent-sessions", `{"groupId":"`+group.ID.String()+`","subjects":[`+body+`]}`)
		if w.Code != want {
			t.Errorf("subjects %s: 期望 %d，得到 %d %s", body, want, w.Code, w.Body.String())
		}
		if want == 201 && !strings.Contains(w.Body.String(), `"subjects":["incident:`+myInc.String()) {
			t.Errorf("subjects 未保存：%s", w.Body.String())
		}
	}
	w = request("POST", "/api/command-policies", `{"groupId":"`+group.ID.String()+`","origin":"ai","pattern":"whoami"}`)
	if w.Code != 201 || !strings.Contains(w.Body.String(), `"mode":"deny"`) {
		t.Fatalf("创建名单: %d %s", w.Code, w.Body.String())
	}
	// 发消息只把会话切到 running 就返回，运行在后台跑完
	w = request("POST", "/api/agent-sessions/"+session.ID.String()+"/messages", `{"prompt":"检查"}`)
	if w.Code != 202 {
		t.Fatalf("后台运行未受理: %d %s", w.Code, w.Body.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for db.AgentSession.GetX(ctx, session.ID).Status != "idle" && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if got := db.AgentSession.GetX(ctx, session.ID); got.Status != "idle" {
		t.Fatalf("后台运行没有回到 idle: %s", got.Status)
	}
	if n := db.SessionMessage.Query().CountX(ctx); n != 2 {
		t.Fatalf("消息未落库: %d", n)
	}
	if w := request("POST", "/api/agent-sessions/"+session.ID.String()+"/cancel", ""); w.Code != 409 {
		t.Errorf("没在运行的会话停止应 409，得到 %d", w.Code)
	}
	db.SessionMessage.Delete().ExecX(ctx)
	db.GroupMember.UpdateOne(member).SetRole("viewer").ExecX(ctx)
	w = request("POST", "/api/agent-sessions", `{"groupId":"`+group.ID.String()+`"}`)
	if w.Code != 403 {
		t.Fatalf("viewer 创建会话: %d", w.Code)
	}
	w = request("GET", "/api/agent-sessions/"+session.ID.String()+"/messages", "")
	if w.Code != 200 {
		t.Fatalf("viewer 读取会话: %d", w.Code)
	}
	for _, raw := range []string{"-1", "bad"} {
		w = request("GET", "/api/agent-sessions/"+session.ID.String()+"/messages?afterSeq="+raw, "")
		if w.Code != 400 {
			t.Fatalf("无效游标: %d", w.Code)
		}
	}
	builders := make([]*ent.SessionMessageCreate, 1002)
	for i := range builders {
		builders[i] = db.SessionMessage.Create().SetSessionID(session.ID).SetSeq(i + 1).SetRole("user").SetContent(json.RawMessage(`{"role":"user","content":"test"}`))
	}
	db.SessionMessage.CreateBulk(builders...).SaveX(ctx)
	w = request("GET", "/api/agent-sessions/"+session.ID.String()+"/messages?afterSeq=1000", "")
	var messages []*ent.SessionMessage
	if err := json.Unmarshal(w.Body.Bytes(), &messages); err != nil || len(messages) != 2 || messages[0].Seq != 1001 {
		t.Fatalf("消息尾部不可读: %d %s", w.Code, w.Body.String())
	}
	w = request("GET", "/api/agent-sessions/"+session.ID.String(), "")
	if w.Code != 200 {
		t.Fatal("会话详情不可读")
	}
	a := db.Asset.Create().SetHostname("host").SetGroupID(group.ID).SaveX(ctx)
	cmd := db.Command.Create().SetKind("exec").SetAssetID(a.ID).SetStatus("unknown").SaveX(ctx)
	w = request("GET", "/api/commands/"+cmd.ID.String(), "")
	if w.Code != 200 {
		t.Fatal("命令状态不可查")
	}
	db.Asset.UpdateOne(a).SetGroupID(other.ID).SaveX(ctx)
	w = request("GET", "/api/commands/"+cmd.ID.String(), "")
	if w.Code != 403 {
		t.Fatal("跨组命令详情泄漏")
	}
	w = request("GET", "/api/approvals?groupId="+group.ID.String(), "")
	if w.Code != 403 {
		t.Fatal("viewer 不得读取审批")
	}
}

type apiPiRunner struct{}

func (apiPiRunner) Run(ctx context.Context, r piruntime.Request, h piruntime.Handler, o piruntime.Observer) (*piruntime.Result, error) {
	for _, message := range []string{`{"role":"user","content":"检查"}`, `{"role":"assistant","content":[{"type":"text","text":"完成"}]}`} {
		if err := o(ctx, piruntime.Event{Type: "event", Event: json.RawMessage(`{"type":"message_end","message":` + message + `}`)}); err != nil {
			return nil, err
		}
	}
	return &piruntime.Result{Response: "完成", StopReason: "stop", Turns: 1}, nil
}
