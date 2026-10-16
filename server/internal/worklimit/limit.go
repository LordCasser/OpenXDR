// Package worklimit 为昂贵子进程提供有界等待与并发限制。
package worklimit

import (
	"context"
	"errors"
)

var ErrBusy = errors.New("执行队列已满，请稍后重试")

type Limit struct{ active, admitted chan struct{} }

func New(active, waiting int) *Limit {
	return &Limit{make(chan struct{}, active), make(chan struct{}, active+waiting)}
}

// Acquire 返回的释放函数只调用一次。排队时响应取消，不启动额外 goroutine。
func (l *Limit) Acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case l.admitted <- struct{}{}:
	default:
		return nil, ErrBusy
	}
	select {
	case l.active <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-l.active
			<-l.admitted
			return nil, err
		}
		return func() { <-l.active; <-l.admitted }, nil
	case <-ctx.Done():
		<-l.admitted
		return nil, ctx.Err()
	}
}
