package worklimit

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBoundedQueueAndCancellation(t *testing.T) {
	l := New(1, 1)
	release, err := l.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		r, err := l.Acquire(ctx)
		if r != nil {
			r()
		}
		done <- err
	}()
	deadline := time.After(time.Second)
	for len(l.admitted) != 2 {
		select {
		case <-deadline:
			t.Fatal("等待者未入队")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if _, err := l.Acquire(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatalf("队列应满: %v", err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("取消未传播: %v", err)
	}
	release()
	release, err = l.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
	if len(l.active) != 0 || len(l.admitted) != 0 {
		t.Fatal("取消或完成后泄漏名额")
	}
}
