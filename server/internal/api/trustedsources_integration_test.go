//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/ent/auditlog"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

// 可信来源只有组管理员能登记与撤销，校验识别条件与有效期，全程落审计；
// 组外看不到；候选列表来自组内核对过出处的 SSH 登录；事件列表标注来源
func TestTrustedSourcesAPI(t *testing.T) {
	ctx, client := testdb.New(t)
	g := client.Group.Create().SetName("ops").SaveX(ctx)
	other := client.Group.Create().SetName("other").SaveX(ctx)
	host := client.Asset.Create().SetHostname("pve1").SetGroupID(g.ID).SaveX(ctx)
	analyst := client.User.Create().SetUsername("ana").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(g.ID).SetUserID(analyst.ID).SetRole("analyst").SaveX(ctx)
	lead := client.User.Create().SetUsername("lead").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(g.ID).SetUserID(lead.ID).SetRole("admin").SaveX(ctx)
	outsider := client.User.Create().SetUsername("out").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(other.ID).SetUserID(outsider.ID).SetRole("admin").SaveX(ctx)

	// 组内一次核对过出处的登录、一次没带登录归属的登录
	const fp = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
	client.Event.Create().SetTs(time.Now().Add(-time.Hour)).SetClassUID(3002).SetSource("agent").SetAssetID(host.ID).
		SetRaw(json.RawMessage(`{"status_id":1,"login_session":{"user":"root","src_ip":"10.1.1.35","auth_method":"publickey","key_type":"ED25519","key_fp":"` + fp + `"}}`)).SaveX(ctx)
	client.Event.Create().SetTs(time.Now().Add(-time.Hour)).SetClassUID(3002).SetSource("agent").SetAssetID(host.ID).
		SetRaw(json.RawMessage(`{"status_id":1}`)).SaveX(ctx)

	h := Handler(client, loadRules(t), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)
	asAnalyst := httptest.NewServer(as(analyst, h))
	t.Cleanup(asAnalyst.Close)
	asLead := httptest.NewServer(as(lead, h))
	t.Cleanup(asLead.Close)
	asOutsider := httptest.NewServer(as(outsider, h))
	t.Cleanup(asOutsider.Close)

	post := func(s *httptest.Server, path, body string) *http.Response {
		t.Helper()
		resp, err := http.Post(s.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	body := `{"groupId":"` + g.ID.String() + `","name":"Termix","reason":"AI 运维插件","keyFingerprint":"` + fp + `","sourceCidr":"10.1.1.35","expiresInDays":90}`

	if resp := post(asAnalyst, "/api/trusted-sources", body); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("组内 analyst 不能登记，得到 %d", resp.StatusCode)
	}
	if resp := post(asOutsider, "/api/trusted-sources", body); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("别组管理员不能登记，得到 %d", resp.StatusCode)
	}
	for _, bad := range []string{
		`{"groupId":"` + g.ID.String() + `","name":"x","loginUser":"root","expiresInDays":30}`,
		`{"groupId":"` + g.ID.String() + `","name":"x","keyFingerprint":"` + fp + `","expiresInDays":0}`,
		`{"groupId":"` + g.ID.String() + `","name":"x","keyFingerprint":"` + fp + `","expiresInDays":400}`,
		`{"groupId":"` + g.ID.String() + `","name":"x","sourceCidr":"10.0.0.0/8","expiresInDays":30}`,
		`{"groupId":"` + g.ID.String() + `","name":"","keyFingerprint":"` + fp + `","expiresInDays":30}`,
	} {
		if resp := post(asLead, "/api/trusted-sources", bad); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s 应被拒绝，得到 %d", bad, resp.StatusCode)
		}
	}
	resp := post(asLead, "/api/trusted-sources", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("组管理员登记应 201，得到 %d", resp.StatusCode)
	}
	var created trustedSourceRow
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.SourceCIDR == nil || *created.SourceCIDR != "10.1.1.35/32" || created.CreatedBy != "lead" ||
		created.ExpiresAt.Before(time.Now().Add(89*24*time.Hour)) {
		t.Fatalf("登记结果不对: %+v", created)
	}
	if n := client.AuditLog.Query().Where(auditlog.ActionEQ("trusted_source_created"), auditlog.TargetEQ(created.ID.String())).CountX(ctx); n != 1 {
		t.Fatalf("登记应落审计，实际 %d 条", n)
	}

	list := func(s *httptest.Server) []trustedSourceRow {
		t.Helper()
		resp, err := http.Get(s.URL + "/api/trusted-sources")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var rows []trustedSourceRow
		if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	if rows := list(asAnalyst); len(rows) != 1 {
		t.Fatalf("组内成员应能看到，实际 %d 条", len(rows))
	}
	if rows := list(asOutsider); len(rows) != 0 {
		t.Fatalf("组外看不到，实际 %d 条", len(rows))
	}

	// 候选：只列核对过出处的登录，并标出已被刚登记的来源覆盖
	cresp, err := http.Get(asLead.URL + "/api/trusted-sources/candidates?groupId=" + g.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	defer cresp.Body.Close()
	var cands []trustedCandidate
	if err := json.NewDecoder(cresp.Body).Decode(&cands); err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 || cands[0].KeyFP == nil || *cands[0].KeyFP != fp || cands[0].Logins != 1 ||
		len(cands[0].SourceIDs) != 1 || cands[0].SourceIDs[0] != created.ID.String() {
		t.Fatalf("候选不对: %+v", cands)
	}

	// 事件列表标注来源
	ev := client.Event.Create().SetTs(time.Now().Add(-time.Minute)).SetClassUID(1007).SetSource("agent").SetAssetID(host.ID).
		SetRaw(json.RawMessage(`{"process":{"cmd_line":"uname -a"}}`)).SaveX(ctx)
	client.Alert.Create().SetTs(ev.Ts).SetRuleID("r").SetSeverity(3).SetEventID(ev.ID).SetAssetID(host.ID).
		SetAutomationID(created.ID).SaveX(ctx)
	eresp, err := http.Get(asAnalyst.URL + "/api/events?classUid=1007")
	if err != nil {
		t.Fatal(err)
	}
	defer eresp.Body.Close()
	var events []eventRow
	if err := json.NewDecoder(eresp.Body).Decode(&events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Automation == nil || events[0].Automation.Name != "Termix" {
		t.Fatalf("事件应标注可信来源: %+v", events)
	}

	revoke := "/api/trusted-sources/" + created.ID.String() + "/revoke"
	if resp := post(asAnalyst, revoke, ""); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("组内 analyst 不能撤销，得到 %d", resp.StatusCode)
	}
	if resp := post(asLead, revoke, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("组管理员撤销应 204，得到 %d", resp.StatusCode)
	}
	if resp := post(asLead, revoke, ""); resp.StatusCode != http.StatusConflict {
		t.Fatalf("重复撤销应 409，得到 %d", resp.StatusCode)
	}
	got := client.TrustedSource.GetX(ctx, created.ID)
	if got.RevokedAt == nil || got.RevokedBy == nil || *got.RevokedBy != "lead" {
		t.Fatalf("撤销应留下时间与操作人: %+v", got)
	}
	if n := client.AuditLog.Query().Where(auditlog.ActionEQ("trusted_source_revoked"), auditlog.TargetEQ(created.ID.String())).CountX(ctx); n != 1 {
		t.Fatalf("撤销应落审计，实际 %d 条", n)
	}
}
