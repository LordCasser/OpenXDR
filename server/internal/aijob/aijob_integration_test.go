//go:build integration

package aijob_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"openxdr/server/internal/aijob"
	"openxdr/server/internal/testdb"
)

// 同一对象同时发起只跑一次；名额照样释放；卡死的 running 不挡重新发起
func TestStartOnePerSubject(t *testing.T) {
	ctx, db := testdb.New(t)
	k := aijob.Key{Kind: "explain", Subject: "e1", Owner: "u1"}
	gate := make(chan struct{})
	var released sync.WaitGroup
	var mu sync.Mutex
	started := 0
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		released.Add(1)
		go func() {
			defer wg.Done()
			_, ok, err := aijob.Start(ctx, db, k, func(context.Context) (any, error) {
				<-gate
				return map[string]any{"ok": true}, nil
			}, released.Done)
			if err != nil {
				t.Error(err)
				return
			}
			if ok {
				mu.Lock()
				started++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if started != 1 {
		t.Fatalf("同时发起 8 次，跑了 %d 次", started)
	}
	close(gate)
	released.Wait()

	// 跑它的进程没了：running 停在很早以前
	old, err := db.AIJob.Create().SetKind("explain").SetSubject("e2").SetOwner("u1").
		SetCreatedAt(time.Now().Add(-time.Hour)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, ok, err := aijob.Start(ctx, db, aijob.Key{Kind: "explain", Subject: "e2", Owner: "u1"},
		func(context.Context) (any, error) { return map[string]any{}, nil }, nil)
	if err != nil || !ok {
		t.Fatalf("卡死的任务挡住了重新发起：ok=%v err=%v", ok, err)
	}
	if j, _ := db.AIJob.Get(ctx, old.ID); j.Status != "failed" {
		t.Fatalf("卡死的任务应记为失败，实际 %s", j.Status)
	}
}
