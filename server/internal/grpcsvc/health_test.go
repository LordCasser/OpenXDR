package grpcsvc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHealthValidation(t *testing.T) {
	now := time.Now()
	h := collectorHealth{BootID: uuid.NewString(), Sequence: 1, ReportedUnixMs: now.UnixMilli(), QueueLimitBytes: 4 << 20, Capabilities: map[string]capability{"process": {Path: "poll", State: "degraded"}}}
	raw, _ := json.Marshal(h)
	if _, err := parseHealth(string(raw), now); err != nil {
		t.Fatal(err)
	}
	h.Capabilities["local-accounts"] = capability{Path: "etc-passwd", State: "unavailable"}
	raw, _ = json.Marshal(h)
	if _, err := parseHealth(string(raw), now); err != nil {
		t.Fatal(err)
	}
	h.Capabilities["files"] = capability{Path: "rdcw", State: "degraded", Reason: "持续 30 分钟收不到文件事件，自检文件改动也没被看到"}
	raw, _ = json.Marshal(h)
	if parsed, err := parseHealth(string(raw), now); err != nil || parsed.Capabilities["files"].Reason == "" {
		t.Fatalf("降级原因丢失: %v", err)
	}
	// 自动重建：未恢复时重建次数跟着原因，恢复后只留恢复次数
	h.Capabilities["files"] = capability{Path: "rdcw", State: "degraded", Reason: "收不到", Rebuilds: 3, Recoveries: 1}
	h.Capabilities["network"] = capability{Path: "etw", State: "active", Recoveries: 2}
	raw, _ = json.Marshal(h)
	if parsed, err := parseHealth(string(raw), now); err != nil || parsed.Capabilities["files"].Rebuilds != 3 || parsed.Capabilities["network"].Recoveries != 2 {
		t.Fatalf("自动重建次数丢失: %v", err)
	}
	h.Receipts = &receiptHealth{Pending: 2, Incomplete: 1}
	raw, _ = json.Marshal(h)
	parsed, err := parseHealth(string(raw), now)
	if err != nil || parsed.Receipts == nil || *parsed.Receipts != *h.Receipts {
		t.Fatalf("回执缓存状态丢失: %v", err)
	}
	for _, change := range []func(*collectorHealth){
		func(h *collectorHealth) { h.Receipts = &receiptHealth{Pending: 256, Incomplete: 1} },
		func(h *collectorHealth) { h.Receipts = &receiptHealth{Pending: ^uint64(0)} },
		func(h *collectorHealth) { h.Sequence = 0 }, func(h *collectorHealth) { h.QueueBytes = 1 << 54 }, func(h *collectorHealth) { h.ReportedUnixMs = now.Add(-6 * time.Minute).UnixMilli() }, func(h *collectorHealth) { h.Capabilities = map[string]capability{"shell": {State: "active"}} }, func(h *collectorHealth) { h.Capabilities = map[string]capability{"process": {State: "perfect"}} },
		func(h *collectorHealth) {
			h.Capabilities = map[string]capability{"process": {State: "active", Reason: "收不到"}}
		},
		func(h *collectorHealth) {
			h.Capabilities = map[string]capability{"process": {State: "degraded", Reason: strings.Repeat("长", 100)}}
		},
		func(h *collectorHealth) {
			h.Capabilities = map[string]capability{"process": {State: "degraded", Rebuilds: 1}}
		},
	} {
		copy := h
		change(&copy)
		raw, _ := json.Marshal(copy)
		if _, err := parseHealth(string(raw), now); err == nil {
			t.Fatal("接受无效状态")
		}
	}
	if _, err := parseHealth(string(raw)+" {}", now); err == nil {
		t.Fatal("接受多个 JSON 对象")
	}
}
