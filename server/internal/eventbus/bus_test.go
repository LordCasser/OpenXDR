package eventbus

import (
	"strings"
	"testing"
	"time"
)

func TestShardStableAndBounded(t *testing.T) {
	for _, key := range []string{"asset-a", "asset-b", "10.0.0.1"} {
		a := shardOf(key, 32)
		b := shardOf(key, 32)
		if a != b || a < 0 || a >= 32 {
			t.Fatalf("分片异常 key=%q a=%d b=%d", key, a, b)
		}
	}
}

func TestQueueRejectsLossyLimits(t *testing.T) {
	for _, tc := range []struct {
		bytes int64
		age   time.Duration
		want  string
	}{{0, 0, "QUEUE_MAX_BYTES_GB"}, {-1, 0, "QUEUE_MAX_BYTES_GB"}, {1024, time.Hour, "QUEUE_MAX_AGE_HOURS"}, {1024, -time.Second, "QUEUE_MAX_AGE_HOURS"}} {
		_, err := NewJetStream("nats://127.0.0.1:1", "test", 1, 1, tc.bytes, tc.age, nil, nil)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("未拒绝丢失配置: %v", err)
		}
	}
}
