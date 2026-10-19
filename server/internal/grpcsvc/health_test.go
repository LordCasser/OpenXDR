package grpcsvc

import (
	"encoding/json"
	"github.com/google/uuid"
	"testing"
	"time"
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
