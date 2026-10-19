//go:build integration

package grpcsvc

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"openxdr/server/ent"
	"openxdr/server/ent/hook"
	"openxdr/server/internal/response"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

// fakeCommandsStream 是 Commands 双向流的可控 fake。
// Recv: 首条返回 agent 认领，随后返回一个命令结果，最后 EOF。
// Send: 记录推送给 agent 的指令。
type fakeCommandsStream struct {
	ctx     context.Context
	msgs    []*pb.CommandResult
	recved  int
	sent    []*pb.Command
	done    chan struct{} // 收到 Send 时通知
	sendBuf []*pb.Command
}

func newFakeCommandsStream(ctx context.Context, msgs []*pb.CommandResult) *fakeCommandsStream {
	return &fakeCommandsStream{ctx: ctx, msgs: msgs, done: make(chan struct{}, 16)}
}

func (f *fakeCommandsStream) Recv() (*pb.CommandResult, error) {
	if f.recved >= len(f.msgs) {
		return nil, io.EOF
	}
	m := f.msgs[f.recved]
	f.recved++
	return m, nil
}
func (f *fakeCommandsStream) Send(c *pb.Command) error {
	f.sent = append(f.sent, c)
	f.sendBuf = append(f.sendBuf, c)
	f.done <- struct{}{}
	return nil
}
func (f *fakeCommandsStream) Context() context.Context     { return f.ctx }
func (f *fakeCommandsStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeCommandsStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeCommandsStream) SetTrailer(metadata.MD)       {}
func (f *fakeCommandsStream) SendMsg(any) error            { return nil }
func (f *fakeCommandsStream) RecvMsg(any) error            { return nil }

var _ grpc.BidiStreamingServer[pb.CommandResult, pb.Command] = (*fakeCommandsStream)(nil)

// 断线重连不重放任何旧动作，但仍接收迟到回执。
func TestAgentCommandsNoReplayAndComplete(t *testing.T) {
	ctx, client := testdb.New(t)
	agentID := uuid.New()

	asset, err := client.Asset.Create().SetHostname("web01").SetAgentID(agentID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hub := response.NewHub(client, true)

	// 已下发未回执的指令（status=sent）不能自动重放。
	// 直接落一条 sent 指令，模拟“早已推给 agent 但连接断了”的状态。
	cmd, err := client.Command.Create().
		SetKind("isolate_host").
		SetAssetID(asset.ID).
		SetStatus("sent").
		SetIssuedBy("admin").
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	for kind := range response.Kinds {
		for _, status := range []string{"pending", "sent", "unknown"} {
			client.Command.Create().SetKind(kind).SetAssetID(asset.ID).SetStatus(status).SaveX(ctx)
		}
	}
	s := &Server{DB: client, Hub: hub}
	// agent 认领后返回执行结果
	agentClaim := &pb.CommandResult{AgentId: agentID.String()}
	result := &pb.CommandResult{
		AgentId: agentID.String(), CommandId: cmd.ID.String(),
		Status: pb.CommandResult_SUCCEEDED, Detail: "ok",
	}
	stream := newFakeCommandsStream(ctx, []*pb.CommandResult{agentClaim, result})

	before := time.Now()
	if err := s.Commands(stream); err != nil {
		t.Fatalf("Commands 失败: %v", err)
	}
	// 指令通道连上即刷新心跳
	if got := client.Asset.GetX(ctx, asset.ID); got.LastSeen.Before(before) {
		t.Errorf("连上指令通道应刷新 last_seen，实际 %v", got.LastSeen)
	}

	if len(stream.sent) != 0 {
		t.Fatalf("重连不得重放任何动作，实际 %d", len(stream.sent))
	}

	// 库中状态应更新为 succeeded，且 detail 落库
	got, err := client.Command.Get(ctx, cmd.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "succeeded" {
		t.Errorf("指令状态应为 succeeded，实际 %q", got.Status)
	}
	if got.Detail == nil || *got.Detail != "ok" {
		t.Errorf("detail 应回写为 ok，实际 %v", got.Detail)
	}
}

func TestCommandStreamReportsReceiptStorageFailure(t *testing.T) {
	ctx, client := testdb.New(t)
	agentID := uuid.New()
	host := client.Asset.Create().SetHostname("receipt-failure").SetAgentID(agentID).SaveX(ctx)
	cmd := client.Command.Create().SetAssetID(host.ID).SetKind("exec").SetStatus("sent").SaveX(ctx)
	client.Command.Use(func(next ent.Mutator) ent.Mutator {
		return hook.CommandFunc(func(ctx context.Context, m *ent.CommandMutation) (ent.Value, error) {
			if state, ok := m.Status(); ok && state == "succeeded" {
				return nil, errors.New("模拟存储失败")
			}
			return next.Mutate(ctx, m)
		})
	})
	hub := response.NewHub(client, true)
	server := &Server{DB: client, Hub: hub}
	stream := newFakeCommandsStream(ctx, []*pb.CommandResult{{AgentId: agentID.String()}, {CommandId: cmd.ID.String(), Status: pb.CommandResult_SUCCEEDED}})
	if err := server.Commands(stream); err == nil || !strings.Contains(err.Error(), "未持久化") {
		t.Fatalf("流未报告失败: %v", err)
	}
	if client.Command.GetX(ctx, cmd.ID).Status != "sent" || len(stream.sent) != 0 || hub.Online(agentID) {
		t.Fatal("失败后伪造完成、重发或残留指令通道")
	}
}
