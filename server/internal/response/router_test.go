package response

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/nats-io/nats.go"
)

// 只有能证明指令没进任何 agent 通道的失败才允许重试；超时、断连等可能已下发的失败不行。
func TestUndeliveredOnlyProvenFailures(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{fmt.Errorf("agent 未连接任何集群节点: %w", nats.ErrNoResponders), true},
		{fmt.Errorf("跨节点指令被拒绝: %w", errConnGone), true},
		{fmt.Errorf("跨节点指令投递失败: %w", context.DeadlineExceeded), false},
		{fmt.Errorf("跨节点指令投递失败: %w", nats.ErrTimeout), false},
		{fmt.Errorf("跨节点指令投递失败: %w", nats.ErrConnectionClosed), false},
		{errors.New("跨节点指令被拒绝: agent 指令队列已满"), false},
		{errors.New("跨节点指令被拒绝: agent 指令连接已失效"), false}, // 只认哨兵错误，不认拼出来的文字
	} {
		if got := undelivered(tc.err); got != tc.want {
			t.Errorf("undelivered(%v) = %t，期望 %t", tc.err, got, tc.want)
		}
	}
}
