//go:build integration

package response

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/hook"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

type auditLostReplyRouter struct {
	*fakeRouter
	accepted bool
}

func (r *auditLostReplyRouter) Deliver(_ context.Context, _ uuid.UUID, _ *pb.Command) error {
	r.accepted = true
	return context.DeadlineExceeded
}

func TestUnknownSurvivesWriteFailure(t *testing.T) {
	ctx, db := testdb.New(t)
	a := db.Asset.Create().SetHostname("local-test").SetAgentID(uuid.New()).SaveX(ctx)
	db.Command.Use(func(next ent.Mutator) ent.Mutator {
		return hook.CommandFunc(func(ctx context.Context, m *ent.CommandMutation) (ent.Value, error) {
			if status, ok := m.Status(); ok && status == "unknown" {
				return nil, errors.New("模拟数据库回写失败")
			}
			return next.Mutate(ctx, m)
		})
	})
	router := &auditLostReplyRouter{fakeRouter: newFakeRouter()}
	hub := NewHub(db, true)
	hub.Router = router
	cmd := "只用于内存路由测试，不执行"
	out, err := hub.Issue(ctx, Request{AssetID: a.ID, Kind: "exec", Cmd: &cmd, DryRun: true, IssuedBy: "audit"})
	if !router.accepted || err == nil {
		t.Fatal("未触发目标分支")
	}
	t.Logf("accepted=%t out_nil=%t unknown_marker=%t error=%v", router.accepted, out == nil, errors.Is(err, ErrDeliveryUnknown), err)
	if !errors.Is(err, ErrDeliveryUnknown) || out == nil {
		t.Fatal("必须保留未知标记与命令 ID")
	}
}

func TestReplayPreservesFields(t *testing.T) {
	ctx, db := testdb.New(t)
	aid := uuid.New()
	a := db.Asset.Create().SetHostname("local-test").SetAgentID(aid).SaveX(ctx)
	hub := NewHub(db, true)
	ch := hub.Attach(aid)
	for _, kind := range []string{"kill_process", "isolate_host"} {
		stored, err := hub.Issue(ctx, Request{AssetID: a.ID, Kind: kind, PID: 1234, AllowEndpoints: []string{"127.0.0.1:8081"}, DryRun: true, IssuedBy: "audit"})
		if err != nil {
			t.Fatal(err)
		}
		original := <-ch
		replay := hub.ToProto(stored)
		t.Logf("kind=%s firstPID=%d replayPID=%d firstAllow=%v replayAllow=%v", kind, original.Pid, replay.Pid, original.AllowEndpoints, replay.AllowEndpoints)
		if replay.Pid != original.Pid || len(replay.AllowEndpoints) != 1 || replay.AllowEndpoints[0] != original.AllowEndpoints[0] {
			t.Fatal("补发丢失参数")
		}
	}
}
