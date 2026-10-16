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
	if !session.DryRun {
		t.Fatal("默认必须 dry-run")
	}
	w = request("POST", "/api/command-policies", `{"groupId":"`+group.ID.String()+`","origin":"ai","pattern":"whoami"}`)
	if w.Code != 201 {
		t.Fatalf("创建名单: %d %s", w.Code, w.Body.String())
	}
	w = request("POST", "/api/agent-sessions/"+session.ID.String()+"/messages", `{"prompt":"检查"}`)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "text/event-stream") || !strings.Contains(w.Body.String(), "event: done") {
		t.Fatalf("SSE 未完成: %d %s", w.Code, w.Body.String())
	}
	if got := db.AgentSession.GetX(ctx, session.ID); got.Status != "idle" {
		t.Fatal("done 前未保存 idle")
	}
	if n := db.SessionMessage.Query().CountX(ctx); n != 2 {
		t.Fatalf("SSE 消息未落库: %d", n)
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
