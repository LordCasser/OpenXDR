//go:build integration

package grpcsvc

import (
	"encoding/json"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
	"testing"
	"time"
)

func TestHealthIndependentIdentityAndOrdering(t *testing.T) {
	ctx, db := testdb.New(t)
	agentID := uuid.New()
	owner := db.Asset.Create().SetHostname("health-owner").SetAgentID(agentID).SaveX(ctx)
	other := uuid.New()
	db.Asset.Create().SetHostname("health-other").SetAgentID(other).SaveX(ctx)
	srv := &Server{DB: db} // 无事件总线、无规则引擎；状态通道仍可用。
	sample := collectorHealth{BootID: uuid.NewString(), Sequence: 2, ReportedUnixMs: time.Now().UnixMilli(), QueueBytes: 1234, QueueLimitBytes: 4 << 20, Capabilities: map[string]capability{"process": {Path: "poll", State: "degraded"}}}
	request := func(id uuid.UUID) *pb.HealthRequest {
		raw, _ := json.Marshal(sample)
		return &pb.HealthRequest{AgentId: id.String(), HealthJson: string(raw)}
	}
	if _, err := srv.ReportHealth(ctxWithCN("host:health-owner"), request(other)); status.Code(err) != codes.PermissionDenied {
		t.Fatal("跨主机写入未被拒绝", err)
	}
	if _, err := srv.ReportHealth(ctxWithCN("host:health-owner"), request(agentID)); err != nil {
		t.Fatal(err)
	}
	first := db.Asset.GetX(ctx, owner.ID)
	var saved map[string]any
	if err := json.Unmarshal(first.CollectorHealth, &saved); err != nil {
		t.Fatal(err)
	}
	if saved["queueBytes"] != float64(1234) || saved["receivedAt"] == nil {
		t.Fatal("状态未入库或缺服务端时间")
	}
	sample.Sequence = 1
	sample.QueueBytes = 0
	if _, err := srv.ReportHealth(ctx, request(agentID)); err != nil {
		t.Fatal(err)
	}
	if string(db.Asset.GetX(ctx, owner.ID).CollectorHealth) != string(first.CollectorHealth) {
		t.Fatal("倒序状态覆盖新快照")
	}
	sample.Sequence = 3
	if _, err := srv.ReportHealth(ctx, request(agentID)); err != nil {
		t.Fatal(err)
	}
	latest := db.Asset.GetX(ctx, owner.ID)
	if string(latest.CollectorHealth) == string(first.CollectorHealth) {
		t.Fatal("新状态未更新")
	}
	sample.BootID = uuid.NewString()
	sample.Sequence = 1
	sample.ReportedUnixMs -= 1000
	if _, err := srv.ReportHealth(ctx, request(agentID)); err != nil {
		t.Fatal(err)
	}
	if string(db.Asset.GetX(ctx, owner.ID).CollectorHealth) != string(latest.CollectorHealth) {
		t.Fatal("旧启动状态覆盖新快照")
	}
}
