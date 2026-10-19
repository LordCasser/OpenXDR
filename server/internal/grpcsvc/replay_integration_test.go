//go:build integration

package grpcsvc

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/ingest"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

// 使用真实数据库处理器，避免仅验证重传 payload 相同却没有覆盖告警副作用。
type replayBus struct{ processor *ingest.Processor }

func (b replayBus) Publish(ctx context.Context, e ingest.Envelope) error {
	return b.processor.Process(ctx, e)
}
func (replayBus) Ready() bool  { return true }
func (replayBus) Close() error { return nil }

type lostAckStream struct{ *fakeAgentStream }

func (s lostAckStream) SendAndClose(*pb.ReportAck) error {
	return errors.New("模拟接收完成后 ACK 丢失")
}

func TestDurableAgentReplayAfterLostAck(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := ingest.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	agentID := uuid.New()
	_, err = client.Asset.Create().SetHostname("durable-replay").SetOs("windows").SetAgentID(agentID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	processor := &ingest.Processor{DB: db, Rules: loadMimikatzRule(t), Suppress: suppress.New(client, 0), Intel: intel.New(client, 0), DedupWindow: time.Hour}
	srv := &Server{DB: client, Events: replayBus{processor}}
	event := &pb.AgentEvent{AgentId: agentID.String(), ClassUid: 1007, TsUnixNs: time.Now().UnixNano(), ProcessGuid: uuid.NewString(), RawJson: `{"process":{"cmd_line":"mimikatz"}}`}
	failed := lostAckStream{&fakeAgentStream{ctx: ctx, events: []*pb.AgentEvent{event}}}
	if err := srv.ReportEvents(failed); err == nil {
		t.Fatal("应返回 ACK 丢失")
	}
	// 新建 gateway 实例与流，模拟重连到另一节点；收到完整 ACK 但不重复事件或告警计数。
	srv = &Server{DB: client, Events: replayBus{processor}}
	retry := &fakeAgentStream{ctx: ctx, events: []*pb.AgentEvent{event}}
	if err := srv.ReportEvents(retry); err != nil {
		t.Fatal(err)
	}
	if retry.ack == nil || retry.ack.Received != 1 {
		t.Fatal("未确认整批")
	}
	if count, err := client.Event.Query().Count(ctx); err != nil || count != 1 {
		t.Fatalf("重投产生重复事件: %d %v", count, err)
	}
	alerts, err := client.Alert.Query().All(ctx)
	if err != nil || len(alerts) != 1 || alerts[0].Count != 1 {
		t.Fatalf("重投产生重复告警或计数: %+v %v", alerts, err)
	}
}
