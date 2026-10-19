//go:build integration

package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
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
	"openxdr/server/internal/triage"
)

func TestAIHostImportReviewedSnapshot(t *testing.T) {
	ctx, db := testdb.New(t)
	owner := db.User.Create().SetUsername("import-owner").SetPasswordHash("unused").SetRole("analyst").SaveX(ctx)
	viewer := db.User.Create().SetUsername("import-viewer").SetPasswordHash("unused").SetRole("viewer").SaveX(ctx)
	group := db.Group.Create().SetName("import-group").SaveX(ctx)
	db.GroupMember.Create().SetUserID(owner.ID).SetGroupID(group.ID).SetRole("admin").ExecX(ctx)
	db.GroupMember.Create().SetUserID(viewer.ID).SetGroupID(group.ID).SetRole("viewer").ExecX(ctx)
	calls := 0
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]string{"role": "assistant", "content": `{"hosts":[{"hostname":"app-prod","address":"192.0.2.10","os":"linux","port":22,"username":"ops","password":"ai-secret-marker","lines":[1]}]}`}}}})
	}))
	defer model.Close()
	vault, _ := hostimport.NewVault(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	service := &hostimport.Service{DB: db, Vault: vault, LLM: triage.NewLLM(model.URL, "test", "", time.Second)}
	handler := HostImports(service, &enroll.Service{}, "", false)
	send := func(u *ent.User, path string, body any) *httptest.ResponseRecorder {
		data, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", path, bytes.NewReader(data))
		r = r.WithContext(auth.WithUser(r.Context(), u))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if strings.Contains(w.Body.String(), "ai-secret-marker") {
			t.Fatal("API 泄露密码")
		}
		return w
	}
	body := map[string]any{"groupId": group.ID, "document": "主机 app-prod，Ubuntu，192.0.2.10，ops 的 SSH 密码 ai-secret-marker。"}
	if w := send(viewer, "/api/host-import/analyze", body); w.Code != 403 || calls != 0 {
		t.Fatal("未授权请求调用模型")
	}
	// 提取在后台跑：POST 立即返回，按组轮询 GET 拿结果
	w := send(owner, "/api/host-import/analyze", body)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"running"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	poll := func(u *ent.User) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/api/host-import/analyze?groupId="+group.ID.String(), nil)
		r = r.WithContext(auth.WithUser(r.Context(), u))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if strings.Contains(w.Body.String(), "ai-secret-marker") {
			t.Fatal("API 泄露密码")
		}
		return w
	}
	var job struct {
		Status string
		Result hostimport.Analysis
	}
	for i := 0; i < 100 && job.Status != "done"; i++ {
		time.Sleep(20 * time.Millisecond)
		if json.Unmarshal(poll(owner).Body.Bytes(), &job) != nil {
			t.Fatal("提取结果解码失败")
		}
	}
	if job.Status != "done" {
		t.Fatalf("提取没跑完：%+v", job)
	}
	if poll(viewer).Code != 403 {
		t.Fatal("非组管理员读到了提取结果")
	}
	for _, j := range db.AIJob.Query().AllX(ctx) {
		if raw, _ := json.Marshal(j); strings.Contains(string(raw), "ai-secret-marker") {
			t.Fatal("任务结果里出现明文密码")
		}
	}
	preview := job.Result
	if db.Asset.Query().CountX(ctx) != 0 || db.HostCredential.Query().CountX(ctx) != 0 {
		t.Fatal("预览提前入库")
	}
	preview.Hosts[0].Hostname = "reviewed-app"
	commit := map[string]any{"groupId": group.ID, "hosts": preview.Hosts, "confirmed": false}
	if w := send(owner, "/api/host-import/confirm", commit); w.Code != 400 {
		t.Fatal("缺少人工确认仍入库")
	}
	commit["confirmed"] = true
	// 模型不可用也不影响确认，且确认不会再调模型。
	model.Close()
	w = send(owner, "/api/host-import/confirm", commit)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	if calls != 1 {
		t.Fatal("确认重复调用模型")
	}
	credential := db.HostCredential.Query().OnlyX(ctx)
	_, secret, err := service.Credential(ctx, credential.ID, group.ID)
	if err != nil || secret.Password != "ai-secret-marker" {
		t.Fatal("凭据未正确加密保存", err)
	}
	if strings.Contains(string(credential.Sealed), "ai-secret-marker") {
		t.Fatal("数据库出现明文")
	}
	if db.AIJob.Query().CountX(ctx) != 0 {
		t.Fatal("导入完成后提取结果应清掉")
	}
	if db.Asset.Query().OnlyX(ctx).Hostname != "reviewed-app" {
		t.Fatal("未保存人工修正")
	}
	if w := send(owner, "/api/host-import/confirm", commit); w.Code != 409 {
		t.Fatal("重复提交未拒绝")
	}
	for _, log := range db.AuditLog.Query().AllX(ctx) {
		raw, _ := json.Marshal(log)
		if strings.Contains(string(raw), "ai-secret-marker") {
			t.Fatal("审计泄露密码")
		}
	}

	var upload bytes.Buffer
	form := multipart.NewWriter(&upload)
	form.WriteField("groupId", group.ID.String())
	file, _ := form.CreateFormFile("file", "handoff.txt")
	file.Write([]byte("主机 192.0.2.20"))
	form.Close()
	r := httptest.NewRequest("POST", "/api/host-import/extract", &upload)
	r.Header.Set("Content-Type", form.FormDataContentType())
	r = r.WithContext(auth.WithUser(r.Context(), owner))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "192.0.2.20") {
		t.Fatal("文档上传提取失败", w.Code)
	}
}
