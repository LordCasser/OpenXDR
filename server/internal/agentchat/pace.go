package agentchat

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"openxdr/server/internal/piruntime"
)

// 收尾时机按本会话实测的模型单轮耗时算：推理端变慢时（单轮从十几秒涨到两三分钟）固定的几分钟余量不够交报告。
const (
	// paceWindow 取最近几轮里最慢的一轮作单轮耗时：样本少，取最大值就是较高分位，变慢时立刻跟上
	paceWindow = 5
	// wrapUpTurnsNeeded 收尾要的模型轮数：写报告一轮、格式不合格退回重写一轮、交完报告的收尾一轮
	wrapUpTurnsNeeded = 3
	// wrapUpMargin 收尾时模型以外的开销：沙箱起容器、取历史、入库
	wrapUpMargin = time.Minute
)

// wrapUpReserve 从运行期限里至少留给收尾的时间（快模型时的下限）
func wrapUpReserve(timeout time.Duration) time.Duration {
	return min(3*time.Minute, timeout/5)
}

// wrapUpLead 剩余时间少于它就截停调查、进入收尾：3 × 单轮 + 固定余量，不少于 wrapUpReserve；
// 至多运行期限的一半，模型再慢也给调查留出一半时间，收尾来不及时由平台出保底报告
func wrapUpLead(timeout, turn time.Duration) time.Duration {
	return min(max(wrapUpTurnsNeeded*turn+wrapUpMargin, wrapUpReserve(timeout)), timeout/2)
}

// pace 记录本轮模型单轮耗时：assistant 消息相对上一条消息（提问或最后一个工具结果）的间隔。
// 工具执行（等审批、长命令）落在 assistant 与其后的工具结果之间，不计入。
type pace struct {
	mu      sync.Mutex
	last    time.Time
	turns   []time.Duration
	changed chan struct{}
}

func newPace(start time.Time) *pace {
	return &pace{last: start, changed: make(chan struct{}, 1)}
}

// mark 记下一条消息的入库时刻
func (p *pace) mark(role string, at time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if role == "assistant" {
		p.turns = append(p.turns, at.Sub(p.last))
		if len(p.turns) > paceWindow {
			p.turns = p.turns[1:]
		}
		select {
		case p.changed <- struct{}{}:
		default:
		}
	}
	p.last = at
}

// turn 最近 paceWindow 轮里最慢的一轮，还没有样本时为 0
func (p *pace) turn() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	var longest time.Duration
	for _, d := range p.turns {
		longest = max(longest, d)
	}
	return longest
}

// observe 包一层 Observer：消息照常交给 record，入库成功后记时刻
func (p *pace) observe(record piruntime.Observer) piruntime.Observer {
	return func(ctx context.Context, event piruntime.Event) error {
		if err := record(ctx, event); err != nil {
			return err
		}
		if event.Type != "event" {
			return nil
		}
		var e struct {
			Type    string `json:"type"`
			Message struct {
				Role string `json:"role"`
			} `json:"message"`
		}
		if json.Unmarshal(event.Event, &e) == nil && e.Type == "message_end" {
			p.mark(e.Message.Role, time.Now())
		}
		return nil
	}
}

// watch 到「期限 − 提前量」时调用 fire；每记一轮模型耗时重算一次。ctx 结束就退出
func (p *pace) watch(ctx context.Context, deadline time.Time, timeout time.Duration, fire func()) {
	for {
		timer := time.NewTimer(time.Until(deadline.Add(-wrapUpLead(timeout, p.turn()))))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-p.changed:
			timer.Stop()
		case <-timer.C:
			fire()
			return
		}
	}
}
