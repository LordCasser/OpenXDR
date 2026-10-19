//go:build integration

package response

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

// 多个 Hub 模拟独立节点；绕过 Auto 的预查询直接竞争创建，稳定覆盖 TOCTOU 窗口。
func TestAutomaticIsolationCreatesAndDispatchesOnce(t *testing.T) {
	ctx, c := testdb.New(t)
	incident, assetID := seedIncident(t, ctx, c, "auto-concurrent")
	asset := c.Asset.GetX(ctx, assetID)
	const workers = 12
	hubs := make([]*Hub, workers)
	channels := make([]chan *pb.Command, workers)
	for i := range hubs {
		hubs[i] = NewHub(c, true)
		channels[i] = hubs[i].Attach(*asset.AgentID)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	ids := make(chan uuid.UUID, workers)
	errs := make(chan error, workers)
	for i := range hubs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			cmd, err := hubs[i].Issue(ctx, Request{automatic: true, AssetID: assetID, IncidentID: &incident, Kind: "isolate_host", IssuedBy: "auto", AllowEndpoints: []string{"127.0.0.1:8081"}})
			if err != nil {
				errs <- err
				return
			}
			ids <- cmd.ID
		}(i)
	}
	close(start)
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var id uuid.UUID
	for got := range ids {
		if id != uuid.Nil && id != got {
			t.Fatal("自动指令 ID 不一致")
		}
		id = got
	}
	if n := c.Command.Query().CountX(ctx); n != 1 {
		t.Fatalf("并发创建了 %d 条指令", n)
	}
	sent := 0
	for _, ch := range channels {
		sent += len(ch)
	}
	if sent != 1 {
		t.Fatalf("实际投递 %d 次", sent)
	}
	// 重建 Hub 后仍返回原记录，不能把 sent/unknown/failed 当作可自动重试。
	for _, status := range []string{"pending", "sent", "unknown", "failed", "succeeded"} {
		c.Command.UpdateOneID(id).SetStatus(status).ExecX(ctx)
		h := NewHub(c, true)
		ch := h.Attach(*asset.AgentID)
		cmd, err := h.Issue(ctx, Request{automatic: true, AssetID: assetID, IncidentID: &incident, Kind: "isolate_host", IssuedBy: "auto"})
		if err != nil || cmd.ID != id || cmd.Status != status || len(ch) != 0 {
			t.Fatalf("重建后重放 %s: %v", status, err)
		}
	}
}

func TestAutomaticIdentityDoesNotDeduplicateManualActions(t *testing.T) {
	ctx, c := testdb.New(t)
	incident, assetID := seedIncident(t, ctx, c, "manual-independent")
	asset := c.Asset.GetX(ctx, assetID)
	h := NewHub(c, true)
	ch := h.Attach(*asset.AgentID)
	// 即使用户名恰好是 auto，人工入口也没有内部 automatic 标记。
	for range 2 {
		if _, err := h.Issue(context.Background(), Request{AssetID: assetID, IncidentID: &incident, Kind: "isolate_host", IssuedBy: "auto"}); err != nil {
			t.Fatal(err)
		}
	}
	if c.Command.Query().CountX(ctx) != 2 || len(ch) != 2 {
		t.Fatal("人工指令被自动幂等规则合并")
	}
}
