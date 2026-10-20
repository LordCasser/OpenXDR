package natsretry

import (
	"context"
	"errors"
	"testing"
	"time"
)

var (
	errGone    = errors.New("肯定未被接收")
	errUnclear = errors.New("可能已被接收")
	fast       = Policy{First: time.Millisecond, Max: 4 * time.Millisecond, Budget: 50 * time.Millisecond}
)

func undelivered(err error) bool { return errors.Is(err, errGone) }

func TestRetryAbsorbsTransient(t *testing.T) {
	calls := 0
	err := fast.Do(context.Background(), func() error {
		if calls++; calls < 3 {
			return errGone
		}
		return nil
	}, undelivered)
	if err != nil || calls != 3 {
		t.Fatalf("瞬断应被吸收: err=%v calls=%d", err, calls)
	}
}

func TestRetryStopsOnAmbiguousError(t *testing.T) {
	calls := 0
	err := fast.Do(context.Background(), func() error {
		if calls++; calls == 1 {
			return errGone
		}
		return errUnclear
	}, undelivered)
	if !errors.Is(err, errUnclear) || calls != 2 {
		t.Fatalf("可能已接收的错误不能再重试: err=%v calls=%d", err, calls)
	}
}

func TestRetryBudgetReturnsLastError(t *testing.T) {
	calls := 0
	start := time.Now()
	err := fast.Do(context.Background(), func() error { calls++; return errGone }, undelivered)
	if !errors.Is(err, errGone) || calls < 2 {
		t.Fatalf("超限后应返回原错误: err=%v calls=%d", err, calls)
	}
	if spent := time.Since(start); spent > fast.Budget+20*time.Millisecond {
		t.Fatalf("重试超出预算: %v", spent)
	}
}

func TestRetryHonorsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := Policy{First: time.Hour, Max: time.Hour, Budget: 2 * time.Hour}.Do(ctx, func() error { calls++; return errGone }, undelivered)
	if !errors.Is(err, errGone) || calls != 1 {
		t.Fatalf("ctx 结束应立即返回最后一次错误: err=%v calls=%d", err, calls)
	}
}
