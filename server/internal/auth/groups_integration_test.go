//go:build integration

package auth_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openxdr/server/ent/groupmember"
	entuser "openxdr/server/ent/user"
)

func send(t *testing.T, ts *httptest.Server, cookie *http.Cookie, method, path, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

type groupView struct {
	ID         string `json:"id"`
	Role       string `json:"role"`
	AssetCount int    `json:"assetCount"`
}

func listGroups(t *testing.T, ts *httptest.Server, cookie *http.Cookie) []groupView {
	t.Helper()
	code, b := send(t, ts, cookie, http.MethodGet, "/api/groups", "")
	if code != http.StatusOK {
		t.Fatalf("列组应 200，got %d", code)
	}
	var out []groupView
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// 组的全生命周期：admin 建组授权，成员只看得到自己的组，删组资产退回未分组。
func TestGroupLifecycle(t *testing.T) {
	ctx, client, ts := setup(t)
	admin := login(t, ts, "admin", "password1")
	viewer := login(t, ts, "viewer", "password1")
	viewerUser, err := client.User.Query().Where(entuser.UsernameEQ("viewer")).Only(ctx)
	if err != nil {
		t.Fatal(err)
	}
	viewerID := viewerUser.ID.String()
	host, err := client.Asset.Create().SetHostname("web-01").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	code, b := send(t, ts, admin, http.MethodPost, "/api/groups", `{"name":"prod"}`)
	if code != http.StatusCreated {
		t.Fatalf("建组应 201，got %d %s", code, b)
	}
	var g groupView
	_ = json.Unmarshal(b, &g)
	if code, _ := send(t, ts, admin, http.MethodPost, "/api/groups", `{"name":"prod"}`); code != http.StatusConflict {
		t.Errorf("重名建组应 409，got %d", code)
	}
	if code, _ := send(t, ts, viewer, http.MethodPost, "/api/groups", `{"name":"x"}`); code != http.StatusForbidden {
		t.Errorf("非 admin 建组应 403，got %d", code)
	}

	if got := listGroups(t, ts, viewer); len(got) != 0 {
		t.Fatalf("非成员不应看到组，got %v", got)
	}
	if code, _ := send(t, ts, admin, http.MethodPut, "/api/groups/"+g.ID+"/members/"+viewerID, `{"role":"analyst"}`); code != http.StatusNoContent {
		t.Fatalf("加成员应 204，got %d", code)
	}
	if code, _ := send(t, ts, admin, http.MethodPut, "/api/groups/"+g.ID+"/members/"+viewerID, `{"role":"viewer"}`); code != http.StatusNoContent {
		t.Fatalf("改成员角色应 204，got %d", code)
	}
	if n, _ := client.GroupMember.Query().Count(ctx); n != 1 {
		t.Fatalf("重复设定不应产生多条成员记录，got %d", n)
	}
	got := listGroups(t, ts, viewer)
	if len(got) != 1 || got[0].Role != "viewer" {
		t.Fatalf("成员应看到组且角色为最新设定，got %v", got)
	}
	if code, _ := send(t, ts, viewer, http.MethodGet, "/api/groups/"+g.ID+"/members", ""); code != http.StatusForbidden {
		t.Errorf("组内非 admin 不应看成员名单，got %d", code)
	}
	if code, _ := send(t, ts, admin, http.MethodGet, "/api/groups/"+g.ID+"/members", ""); code != http.StatusOK {
		t.Errorf("admin 应能看成员名单，got %d", code)
	}

	if code, _ := send(t, ts, admin, http.MethodPut, "/api/groups/"+g.ID+"/assets/"+host.ID.String(), ""); code != http.StatusNoContent {
		t.Fatalf("资产归组应 204，got %d", code)
	}
	if got := listGroups(t, ts, admin); len(got) != 1 || got[0].AssetCount != 1 || got[0].Role != "admin" {
		t.Fatalf("admin 应看到组内 1 台资产，got %v", got)
	}
	_, b = send(t, ts, admin, http.MethodPost, "/api/groups", `{"name":"dev"}`)
	var other groupView
	_ = json.Unmarshal(b, &other)
	if code, _ := send(t, ts, admin, http.MethodDelete, "/api/groups/"+other.ID+"/assets/"+host.ID.String(), ""); code != http.StatusConflict {
		t.Errorf("从非所属组移出资产应 409，got %d", code)
	}

	if code, _ := send(t, ts, admin, http.MethodDelete, "/api/groups/"+g.ID, ""); code != http.StatusNoContent {
		t.Fatalf("删组应 204，got %d", code)
	}
	if a, _ := client.Asset.Get(ctx, host.ID); a.GroupID != nil {
		t.Error("删组后资产应退回未分组")
	}
	if n, _ := client.GroupMember.Query().Where(groupmember.UserIDEQ(viewerUser.ID)).Count(ctx); n != 0 {
		t.Errorf("删组后成员关系应清掉，got %d", n)
	}
}
