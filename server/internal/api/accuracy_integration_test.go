//go:build integration

package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/internal/review"
	"openxdr/server/internal/testdb"
)

type titles map[string]string

func (t titles) TitleOf(id string) string { return t[id] }

// 只有人写理由的结案算独立判断；采纳 AI 与自动结案只计数。漏判看 AI 判良性里属实的，误判看 AI 告警里误报的
func TestAIAccuracy(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	now := time.Now()
	mk := func(verdict, model, status, by string, source *string, at time.Time, rules ...string) {
		v, _ := json.Marshal(map[string]any{"verdict": verdict, "model": model})
		if model == "" {
			v, _ = json.Marshal(map[string]any{"verdict": verdict})
		}
		inc := client.Incident.Create().SetGraph(json.RawMessage(`{}`)).SetTitle(verdict + "-" + status).SetAiVerdict(v).
			SetStatus(status).SetResolvedBy(by).SetResolvedAt(at).SetResolution("x").SetNillableResolutionSource(source).SaveX(ctx)
		for _, r := range rules {
			client.Alert.Create().SetTs(at).SetRuleID(r).SetSeverity(3).SetIncidentID(inc.ID).SaveX(ctx)
		}
	}
	adopted := "ai_verdict"
	mk("benign", "m1", "closed", "alice", nil, now, "r1", "r2")         // 漏判
	mk("benign", "m1", "false_positive", "alice", nil, now, "r1")       // 良性判对
	mk("suspicious", "m2", "false_positive", "bob", nil, now, "r2")     // 误判
	mk("malicious", "m2", "closed", "bob", nil, now, "r2")              // 告警判对
	mk("benign", "", "false_positive", "alice", &adopted, now, "r1")    // 采纳 AI：不算
	mk("benign", "m1", "false_positive", review.ClosedBy, nil, now)     // 自动结案：不算
	mk("benign", "m1", "closed", "alice", nil, now.AddDate(0, 0, -200)) // 窗口外
	// 早期版本结案不记时间与结案人：照样算人的独立判断
	client.Incident.Create().SetGraph(json.RawMessage(`{}`)).SetAiVerdict(json.RawMessage(`{"verdict":"benign"}`)).
		SetStatus("false_positive").SetResolution("老数据").ExecX(ctx)

	ts := httptest.NewServer(AIAccuracy(db, titles{"r1": "规则一"}))
	t.Cleanup(ts.Close)
	resp, err := http.Get(ts.URL + "/api/settings/ai/accuracy?days=90")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Total       accuracyCounts `json:"total"`
		ByModel     []accuracyRow  `json:"byModel"`
		ByRule      []accuracyRow  `json:"byRule"`
		Missed      []accuracyCase `json:"missed"`
		FalseAlarms []accuracyCase `json:"falseAlarms"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	want := accuracyCounts{Reviewed: 5, AIBenign: 3, Missed: 1, AIAlarm: 2, FalseAlarm: 1, Adopted: 1, Auto: 1}
	if out.Total != want {
		t.Fatalf("总体口径不对: %+v", out.Total)
	}
	models := map[string]accuracyCounts{}
	for _, m := range out.ByModel {
		models[m.Key] = m.accuracyCounts
	}
	if m := models["m1"]; m.Reviewed != 2 || m.Missed != 1 || m.Auto != 1 {
		t.Fatalf("m1 统计不对: %+v", m)
	}
	if m := models[""]; m.Adopted != 1 || m.Reviewed != 1 {
		t.Fatalf("没记录模型的旧结论应单独成组: %+v", m)
	}
	rules := map[string]accuracyRow{}
	for _, r := range out.ByRule {
		rules[r.Key] = r
	}
	if r := rules["r1"]; r.Title != "规则一" || r.Reviewed != 2 || r.Missed != 1 || r.Adopted != 1 {
		t.Fatalf("r1 统计不对: %+v", r)
	}
	if r := rules["r2"]; r.Reviewed != 3 || r.Missed != 1 || r.FalseAlarm != 1 {
		t.Fatalf("一个事件带多条规则时每条各算一次: %+v", r)
	}
	if len(out.Missed) != 1 || out.Missed[0].Model != "m1" || len(out.FalseAlarms) != 1 || out.FalseAlarms[0].ResolvedBy != "bob" {
		t.Fatalf("案例列表不对: %+v %+v", out.Missed, out.FalseAlarms)
	}
}
