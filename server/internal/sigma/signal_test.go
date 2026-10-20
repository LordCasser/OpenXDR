package sigma

import (
	"strings"
	"testing"
)

const signalRule = `title: 信号
id: sig-1
openxdr_signal: true
level: informational
logsource: {category: process_creation, product: linux}
detection:
  selection: {CommandLine: bash}
  condition: selection
`

// 信号规则只从 EvaluateSignals 出来：Evaluate 的调用方都会拿命中出告警
func TestSignalRuleNeverAlerts(t *testing.T) {
	rule, err := Compile([]byte(signalRule))
	if err != nil {
		t.Fatal(err)
	}
	if !rule.Signal {
		t.Fatal("openxdr_signal: true 应编译成信号规则")
	}
	alerting, err := Compile([]byte(strings.Replace(strings.Replace(signalRule, "openxdr_signal: true\n", "", 1), "sig-1", "alert-1", 1)))
	if err != nil {
		t.Fatal(err)
	}
	state := &engineState{rules: []*Rule{rule, alerting}, byID: map[string]*Rule{rule.ID: rule, alerting.ID: alerting}}
	state.index()
	engine := &Engine{}
	engine.state.Store(state)
	raw := map[string]any{"process": map[string]any{"cmd_line": "bash"}}
	if hits := engine.Evaluate(1007, "linux", raw); len(hits) != 1 || hits[0].ID != "alert-1" {
		t.Fatalf("Evaluate 只应返回告警规则: %v", hits)
	}
	if hits := engine.EvaluateSignals(1007, "linux", raw); len(hits) != 1 || hits[0].ID != "sig-1" {
		t.Fatalf("EvaluateSignals 只应返回信号规则: %v", hits)
	}
}

func TestSignalRuleRejectsAmbiguousMarker(t *testing.T) {
	for name, text := range map[string]string{
		"false":           strings.Replace(signalRule, "openxdr_signal: true", "openxdr_signal: false", 1),
		"字符串":             strings.Replace(signalRule, "openxdr_signal: true", "openxdr_signal: \"yes\"", 1),
		"非 informational": strings.Replace(signalRule, "level: informational", "level: low", 1),
		"缺 level":         strings.Replace(signalRule, "level: informational\n", "", 1),
	} {
		if _, err := Compile([]byte(text)); err == nil {
			t.Errorf("%s: 应拒绝加载", name)
		}
	}
}
