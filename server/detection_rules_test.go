package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDetectionRulesConfiguration(t *testing.T) {
	base, seq := t.TempDir(), t.TempDir()
	write := func(path, text string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(base, "base.yml"), `id: base
title: Base
logsource:
  category: process_creation
detection:
  selection:
    marker: yes
  condition: selection
`)
	write(filepath.Join(seq, "temporal.yml"), `id: temporal
title: Repeated activity
author: Test maintainer
kind: event_count
within: 1m
rules: [base]
threshold: 2
level: high
`)
	catalog, store, err := loadDetectionRules(context.Background(), base, seq, 0)
	if err != nil || store == nil {
		t.Fatalf("启用失败: %v", err)
	}
	if catalog != store || catalog.TitleOf("temporal") != "Repeated activity" || catalog.AuthorOf("temporal") != "Test maintainer" {
		t.Fatal("检测和展示必须共用规则目录")
	}
	rules := catalog.Rules()
	if len(rules) != 2 {
		t.Fatalf("未展示基础和时序规则: %+v", rules)
	}
	if rules[1].Severity != 4 || rules[1].WindowSeconds != 60 || rules[1].Threshold != 2 {
		t.Fatalf("时序元数据不完整: %+v", rules[1])
	}
	if len(catalog.Evaluate(1007, "linux", map[string]any{"marker": "yes"})) != 1 {
		t.Fatal("单事件不能直接产生时序命中")
	}
	plain, disabled, err := loadDetectionRules(context.Background(), base, "", 0)
	if err != nil || disabled != nil || len(plain.Rules()) != 1 {
		t.Fatalf("未配置时应保留单事件引擎: %v", err)
	}
	write(filepath.Join(seq, "temporal.yml"), "kind: invalid")
	if _, _, err := loadDetectionRules(context.Background(), base, seq, 0); err == nil {
		t.Fatal("坏配置必须拒绝启动")
	}
}
