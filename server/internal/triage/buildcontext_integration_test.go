//go:build integration

package triage

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/testdb"
)

// buildContext 生成给 LLM 的研判上下文：标题、图、按时间排序的告警明细，
// 超长事件原文截断。
func TestBuildContext(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()

	// 超长事件原文（>500，应截断加省略号）
	longRaw := json.RawMessage(`{"process":{"name":"` + strings.Repeat("x", 600) + `"}}`)
	evt1, err := client.Event.Create().
		SetTs(now.Add(-2 * time.Minute)).SetClassUID(1007).SetSource("agent").
		SetRaw(longRaw).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	evt2, err := client.Event.Create().
		SetTs(now.Add(-time.Minute)).SetClassUID(1007).SetSource("agent").
		SetRaw(json.RawMessage(`{"process":{"name":"parent.exe"}}`)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	title := "SSH brute force"
	inc, err := client.Incident.Create().
		SetStatus("open").SetTitle(title).SetGraph(json.RawMessage(`{"nodes":[]}`)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Alert.Create().
		SetTs(now).SetRuleID("r-loud").SetSeverity(4).SetCount(3).
		SetEventID(evt1.ID).SetIncidentID(inc.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Alert.Create().
		SetTs(now).SetRuleID("r-quiet").SetSeverity(2).
		SetEventID(evt2.ID).SetIncidentID(inc.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}
	// 复发归并进来的同类告警：汇总里要能看到重复次数
	if _, err := client.Alert.Create().
		SetTs(now.Add(time.Hour)).SetRuleID("r-quiet").SetSeverity(2).
		SetEventID(evt2.ID).SetIncidentID(inc.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}

	e := &Engine{DB: client}
	out, err := e.buildContext(ctx, inc)
	if err != nil {
		t.Fatalf("buildContext 失败: %v", err)
	}
	for _, want := range []string{
		title,          // 标题
		`{"nodes":[]}`, // 图
		"r-loud", "r-quiet", "severity=4", "count=3",
		"parent.exe", // 未截断事件原文
		"…",          // 超长事件截断标记
		"- r-quiet：2 条告警（去重前累计命中 2 次）\n- r-loud：1 条告警（去重前累计命中 3 次）", // 按规则汇总，多的在前
	} {
		if !strings.Contains(out, want) {
			t.Errorf("上下文缺少 %q，实际:\n%s", want, out)
		}
	}
}

// 同规则或同主机的人工结案回流进上下文，带 AI 当时的判断与备注；无关事件不出现。
func TestBuildContextCaseHistory(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()
	host := client.Asset.Create().SetHostname("h1").SaveX(ctx)
	other := client.Asset.Create().SetHostname("h2").SaveX(ctx)
	mk := func(status, title, verdict, note, rule string, asset uuid.UUID) {
		c := client.Incident.Create().SetStatus(status).SetTitle(title).SetGraph(json.RawMessage(`{}`))
		if verdict != "" {
			c.SetAiVerdict(json.RawMessage(`{"verdict":"` + verdict + `"}`))
		}
		if note != "" {
			c.SetResolution(note)
		}
		inc := c.SaveX(ctx)
		client.Alert.Create().SetTs(now.Add(-24 * time.Hour)).SetRuleID(rule).SetSeverity(3).
			SetAssetID(asset).SetIncidentID(inc.ID).SaveX(ctx)
	}
	mk("false_positive", "扫描器噪声", "malicious", "运维巡检脚本", "r-noisy", other.ID)
	mk("closed", "同机真入侵", "benign", "已确认被植入后门并重装", "r-other", host.ID)
	mk("triaged", "未结案的", "benign", "", "r-noisy", host.ID)
	mk("closed", "无关事件", "", "", "r-unrelated", other.ID)

	inc := client.Incident.Create().SetStatus("open").SetTitle("新事件").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	client.Alert.Create().SetTs(now).SetRuleID("r-noisy").SetSeverity(3).SetAssetID(host.ID).SetIncidentID(inc.ID).SaveX(ctx)

	out, err := (&Engine{DB: client}).buildContext(ctx, inc)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"历史结案参考", "「扫描器噪声」：AI 判 malicious，人工结案为误报或良性。备注：运维巡检脚本",
		"「同机真入侵」：AI 判 benign，人工结案为属实已处置。备注：已确认被植入后门并重装"} {
		if !strings.Contains(out, want) {
			t.Errorf("上下文缺少 %q：\n%s", want, out)
		}
	}
	for _, bad := range []string{"未结案的", "无关事件", "「新事件」："} {
		if strings.Contains(out, bad) {
			t.Errorf("不该出现 %q：\n%s", bad, out)
		}
	}

	lone := client.Incident.Create().SetStatus("open").SetTitle("另一事件").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	client.Alert.Create().SetTs(now).SetRuleID("r-clean").SetSeverity(3).SetIncidentID(lone.ID).SaveX(ctx)
	out2, err := (&Engine{DB: client}).buildContext(ctx, lone)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out2, "历史结案参考") {
		t.Errorf("无案例时不该有该段落：\n%s", out2)
	}
}
