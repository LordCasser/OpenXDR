//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
	"openxdr/server/internal/triage"
)

// 问 AI：按进程链、同一进程、子进程、同一连接、同一远端、前后同主机关联；只取调用者能看的主机；
// 模型挑出的相关日志只能来自候选；没配模型时解读返回 503
func TestEventAI(t *testing.T) {
	ctx, client := testdb.New(t)
	g, _ := client.Group.Create().SetName("g").Save(ctx)
	other, _ := client.Group.Create().SetName("o").Save(ctx)
	web, _ := client.Asset.Create().SetHostname("web").SetIPAddrs([]string{"10.0.0.1"}).SetGroupID(g.ID).Save(ctx)
	db2, _ := client.Asset.Create().SetHostname("db").SetIPAddrs([]string{"10.0.0.2"}).SetGroupID(g.ID).Save(ctx)
	hidden, _ := client.Asset.Create().SetHostname("hidden").SetGroupID(other.ID).Save(ctx)
	analyst, _ := client.User.Create().SetUsername("ana").SetPasswordHash("x").SetRole("analyst").Save(ctx)
	_ = client.GroupMember.Create().SetGroupID(g.ID).SetUserID(analyst.ID).SetRole("analyst").Exec(ctx)

	now := time.Now()
	mk := func(asset *ent.Asset, ts time.Time, guid, parent *uuid.UUID, conn string, raw string) *ent.Event {
		c := client.Event.Create().SetTs(ts).SetClassUID(1007).SetSource("agent").SetAssetID(asset.ID).SetRaw(json.RawMessage(raw))
		if guid != nil {
			c.SetProcessGUID(*guid)
		}
		if parent != nil {
			c.SetParentProcessGUID(*parent)
		}
		if conn != "" {
			c.SetClassUID(4001).SetConnTuple(conn)
		}
		return c.SaveX(ctx)
	}
	sshd, bash, child := uuid.New(), uuid.New(), uuid.New()
	parent := mk(web, now.Add(-time.Hour), &sshd, nil, "", `{"process":{"name":"sshd"}}`)
	target := mk(web, now, &bash, &sshd, "", `{"process":{"name":"bash","cmd_line":"bash -i"}}`)
	conn := mk(web, now.Add(time.Second), &bash, nil, "tcp:10.0.0.1:40000>203.0.113.9:4444", `{"dst_endpoint":{"ip":"203.0.113.9","port":4444}}`)
	kid := mk(web, now.Add(2*time.Second), &child, &bash, "", `{"process":{"name":"id"}}`)
	peer := mk(db2, now.Add(-time.Hour), nil, nil, "tcp:10.0.0.2:50000>203.0.113.9:4444", `{}`)
	_ = mk(hidden, now.Add(-time.Hour), nil, nil, "tcp:10.9.9.9:50000>203.0.113.9:4444", `{}`)
	near := mk(web, now.Add(-time.Minute), nil, nil, "", `{"file":{"path":"/tmp/x"}}`)
	_ = mk(web, now.Add(-time.Hour), nil, nil, "", `{"file":{"path":"/tmp/old"}}`)

	llmCalls := 0
	llmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		llmCalls++
		var body struct{ Messages []triage.Message }
		_ = json.NewDecoder(r.Body).Decode(&body)
		if !strings.Contains(body.Messages[1].Content, conn.ID.String()) || strings.Contains(body.Messages[1].Content, "10.9.9.9") {
			t.Errorf("候选应包含同进程连接、不应包含别组主机")
		}
		reply := `{"verdict":"malicious","title":"反弹 shell","summary":"sshd 拉起 bash 连外部 4444","points":["连 4444"],"related":[{"id":"` + conn.ID.String() + `","why":"外连"},{"id":"` + uuid.NewString() + `","why":"编的"}],"next":["查登录"]}`
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": reply}}}})
	}))
	defer llmSrv.Close()
	llm := triage.NewLLM(llmSrv.URL, "m", "", 10*time.Second)
	ts := httptest.NewServer(as(analyst, EventAI(client, llm)))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/events/" + target.ID.String() + "/related")
	if err != nil {
		t.Fatal(err)
	}
	var groups []relatedGroup
	_ = json.NewDecoder(resp.Body).Decode(&groups)
	resp.Body.Close()
	got := map[string][]uuid.UUID{}
	for _, g := range groups {
		for _, e := range g.Events {
			got[g.Relation] = append(got[g.Relation], e.ID)
		}
	}
	want := map[string][]uuid.UUID{"ancestor": {parent.ID}, "process": {conn.ID}, "child": {kid.ID}, "nearby": {near.ID}}
	for rel, ids := range want {
		if len(got[rel]) != len(ids) || got[rel][0] != ids[0] {
			t.Errorf("%s 应为 %v，得到 %v", rel, ids, got[rel])
		}
	}
	if len(got["connection"]) != 0 || len(got["peer"]) != 0 {
		t.Errorf("target 自己没有连接，不该有连接类关联: %v", got)
	}

	// 从连接这条出发：别的主机连同一远端要出现，别组的不出现
	resp, _ = http.Get(ts.URL + "/api/events/" + conn.ID.String() + "/related")
	groups = nil
	_ = json.NewDecoder(resp.Body).Decode(&groups)
	resp.Body.Close()
	var peers []uuid.UUID
	for _, g := range groups {
		if g.Relation == "peer" {
			for _, e := range g.Events {
				peers = append(peers, e.ID)
			}
		}
	}
	if len(peers) != 1 || peers[0] != peer.ID {
		t.Errorf("同一远端只应关联到本组的 db: %v", peers)
	}

	resp, _ = http.Post(ts.URL+"/api/events/"+target.ID.String()+"/explain", "application/json", nil)
	var x struct {
		Verdict string
		Related []struct{ ID uuid.UUID }
	}
	_ = json.NewDecoder(resp.Body).Decode(&x)
	resp.Body.Close()
	if resp.StatusCode != 200 || x.Verdict != "malicious" || len(x.Related) != 1 || x.Related[0].ID != conn.ID || llmCalls != 1 {
		t.Fatalf("解读不对: %d %+v", resp.StatusCode, x)
	}

	hiddenEvent := mk(hidden, now, nil, nil, "", `{}`)
	if resp, _ := http.Get(ts.URL + "/api/events/" + hiddenEvent.ID.String() + "/related"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("别组主机的日志应 404，得到 %d", resp.StatusCode)
	}
	noAI := httptest.NewServer(as(analyst, EventAI(client, triage.NewLLM("", "", "", time.Second))))
	defer noAI.Close()
	if resp, _ := http.Post(noAI.URL+"/api/events/"+target.ID.String()+"/explain", "application/json", nil); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("没配模型应 503，得到 %d", resp.StatusCode)
	}
}
