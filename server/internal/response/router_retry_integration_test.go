//go:build integration

package response

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"

	"openxdr/server/internal/natsretry"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

var shortRetry = natsretry.Policy{First: 50 * time.Millisecond, Max: 100 * time.Millisecond, Budget: 400 * time.Millisecond}

// localNATS 起一个只做 core NATS 的临时实例，不碰 NATS_URL 指向的共享集群。
func localNATS(t *testing.T) string {
	t.Helper()
	binary, err := exec.LookPath("nats-server")
	if err != nil {
		t.Skip("未安装 nats-server")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cmd := exec.Command(binary, "-a", "127.0.0.1", "-p", fmt.Sprint(port))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Signal(os.Interrupt); _ = cmd.Wait() })
	url := fmt.Sprintf("nats://127.0.0.1:%d", port)
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if nc, err := nats.Connect(url, nats.Timeout(100*time.Millisecond)); err == nil {
			nc.Close()
			return url
		}
	}
	t.Fatal("临时 NATS 未就绪")
	return ""
}

func newTestRouter(t *testing.T, url, instance string) *NATSRouter {
	t.Helper()
	r, err := NewNATSRouter(url, instance)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

// agent 断线重连换节点的空档里 no responders：投递方重试吸收，agent 挂上后只送达一次。
func TestNATSRouterRetriesUntilAgentAttaches(t *testing.T) {
	url := localNATS(t)
	a, b := newTestRouter(t, url, "node-a"), newTestRouter(t, url, "node-b")
	agentID := uuid.New()
	var delivered atomic.Int32
	go func() {
		time.Sleep(time.Second)
		a.Attach(agentID, func(*pb.Command) error { delivered.Add(1); return nil })
	}()
	if err := b.Deliver(context.Background(), agentID, &pb.Command{Id: uuid.NewString(), Cmd: "whoami"}); err != nil {
		t.Fatalf("重连空档应被重试吸收: %v", err)
	}
	if got := delivered.Load(); got != 1 {
		t.Fatalf("应恰好送达一次，实际 %d", got)
	}
}

// 持有订阅的节点回「连接已失效」（旧连接还没退订）同样证明没下发，可以重试到新连接。
func TestNATSRouterRetriesStaleConnection(t *testing.T) {
	url := localNATS(t)
	b := newTestRouter(t, url, "node-b")
	agentID := uuid.New()
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	var calls atomic.Int32
	if _, err := nc.QueueSubscribe("openxdr.commands."+agentID.String(), "agent-"+agentID.String(), func(msg *nats.Msg) {
		if calls.Add(1) == 1 {
			_ = msg.Respond([]byte(errConnGone.Error()))
			return
		}
		_ = msg.Respond([]byte("ok"))
	}); err != nil {
		t.Fatal(err)
	}
	_ = nc.Flush()
	if err := b.Deliver(context.Background(), agentID, &pb.Command{Id: uuid.NewString()}); err != nil || calls.Load() != 2 {
		t.Fatalf("旧连接拒收后应重试成功: err=%v calls=%d", err, calls.Load())
	}
}

// 重试超限：仍按原口径记 unknown，迟到回执能回填真实结果。
func TestNATSRouterExhaustedRetryStaysUnknown(t *testing.T) {
	url := localNATS(t)
	ctx, db := testdb.New(t)
	agentID := uuid.New()
	asset := db.Asset.Create().SetHostname("retry-exhausted").SetAgentID(agentID).SaveX(ctx)
	router := newTestRouter(t, url, "node-b")
	router.retry = shortRetry
	h := NewHub(db, true)
	h.Router = router
	line := "whoami"
	start := time.Now()
	cmd, err := h.IssueExec(ctx, Request{AssetID: asset.ID, Kind: "exec", Cmd: &line})
	if err != nil {
		t.Fatal(err)
	}
	if spent := time.Since(start); spent > 3*time.Second {
		t.Fatalf("重试没有上限: %v", spent)
	}
	if cmd.Status != "unknown" || cmd.CompletedAt != nil || cmd.Detail == nil {
		t.Fatalf("超限后应维持 unknown: %+v", cmd)
	}
	if err := h.Complete(ctx, agentID, &pb.CommandResult{CommandId: cmd.ID.String(), Status: pb.CommandResult_SUCCEEDED, Stdout: "root"}); err != nil {
		t.Fatal(err)
	}
	if got := db.Command.GetX(ctx, cmd.ID); got.Status != "succeeded" || got.Stdout == nil || *got.Stdout != "root" {
		t.Fatalf("迟到回执应回填 unknown: %+v", got)
	}
}

// 远端收下指令但回复丢失（这里在收到后掐断投递方连接模拟）：可能已执行，只投一次、记 unknown，绝不重发。
func TestNATSRouterNoRetryWhenMaybeDelivered(t *testing.T) {
	url := localNATS(t)
	ctx, db := testdb.New(t)
	agentID := uuid.New()
	asset := db.Asset.Create().SetHostname("maybe-delivered").SetAgentID(agentID).SaveX(ctx)
	router := newTestRouter(t, url, "node-b")
	router.retry = natsretry.Policy{First: 10 * time.Millisecond, Max: 10 * time.Millisecond, Budget: 5 * time.Second}
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	var received atomic.Int32
	if _, err := nc.QueueSubscribe("openxdr.commands."+agentID.String(), "agent-"+agentID.String(), func(*nats.Msg) {
		received.Add(1)
		router.nc.Close()
	}); err != nil {
		t.Fatal(err)
	}
	_ = nc.Flush()
	h := NewHub(db, true)
	h.Router = router
	line := "id"
	cmd, err := h.IssueExec(ctx, Request{AssetID: asset.ID, Kind: "exec", Cmd: &line})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if got := received.Load(); got != 1 {
		t.Fatalf("可能已下发的指令被重发: 收到 %d 次", got)
	}
	if cmd.Status != "unknown" || cmd.CompletedAt != nil {
		t.Fatalf("可能已下发应记 unknown: %+v", cmd)
	}
}
