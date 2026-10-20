// Package natsretry 吸收 NATS / JetStream 选主瞬断：只重试调用方能证明「对端肯定没收下」的错误，
// 退避有界、总时长有上限，超限后原样返回最后一次错误，判定口径仍由调用方决定。
package natsretry

import (
	"context"
	"time"
)

// Policy 退避参数：首次等待 First，逐次翻倍到 Max 封顶；从首次尝试起算，
// 下一次尝试会晚于 Budget 就不再等。
type Policy struct {
	First, Max, Budget time.Duration
}

// Default 覆盖一次 JetStream 选主（通常一两秒内完成），又不让上报连接或指令下发卡太久。
var Default = Policy{First: 100 * time.Millisecond, Max: time.Second, Budget: 5 * time.Second}

// Do 执行 op；只有 undelivered 判定为「肯定未被接收」的错误才重试，成功或其它错误立即返回。
// 预算耗尽或 ctx 结束时返回最后一次 op 的错误，不用 ctx 错误掩盖真实原因。
func (p Policy) Do(ctx context.Context, op func() error, undelivered func(error) bool) error {
	start, wait := time.Now(), p.First
	for {
		err := op()
		if err == nil || !undelivered(err) || time.Since(start)+wait > p.Budget {
			return err
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return err
		case <-timer.C:
		}
		wait = min(wait*2, p.Max)
	}
}
