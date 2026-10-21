//go:build integration

package incidentstate

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/integrationevent"
	"openxdr/server/internal/testdb"
)

func TestOutboxAtomicityAndSnapshot(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("A").SaveX(ctx)
	a := db.Asset.Create().SetHostname("host").SetGroupID(g.ID).SaveX(ctx)
	inc := db.Incident.Create().SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	ev := db.Event.Create().SetTs(time.Now()).SetClassUID(1007).SetSource("agent").SetAssetID(a.ID).SetRaw(json.RawMessage(`{}`)).SaveX(ctx)
	db.Alert.Create().SetTs(time.Now()).SetSeverity(3).SetRuleID("rule").SetEventID(ev.ID).SetAssetID(a.ID).SetIncidentID(inc.ID).SaveX(ctx)
	tx, err := db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tx.Incident.UpdateOneID(inc.ID).SetStatus("closed").ExecX(ctx)
	if err = Record(ctx, tx, inc.ID, StatusChanged, Origin{Kind: "system"}, "open"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if db.Incident.GetX(ctx, inc.ID).Status != "open" || db.IntegrationEvent.Query().CountX(ctx) != 0 {
		t.Fatal("回滚留下状态或消息")
	}
	tx, err = db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tx.Incident.UpdateOneID(inc.ID).SetStatus("closed").ExecX(ctx)
	if err = Record(ctx, tx, inc.ID, StatusChanged, Origin{Kind: "system"}, "open"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	event := db.IntegrationEvent.Query().Where(integrationevent.IncidentIDEQ(inc.ID)).OnlyX(ctx)
	if event.Revision != 1 || len(event.GroupIds) != 1 || event.GroupIds[0] != g.ID.String() {
		t.Fatal("版本或历史授权快照错误")
	}
	var payload Event
	if err = json.Unmarshal(event.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data["previousStatus"] != "open" || payload.Data["status"] != "closed" || payload.EventID != event.ID {
		t.Fatal("消息内容错误")
	}
	db.Asset.UpdateOne(a).ClearGroupID().ExecX(ctx)
	if db.IntegrationEvent.GetX(ctx, event.ID).GroupIds[0] != g.ID.String() {
		t.Fatal("历史事件被改变")
	}
}

func TestOutboxFailureRollsBackState(t *testing.T) {
	ctx, db := testdb.New(t)
	inc := db.Incident.Create().SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	db.IntegrationEvent.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(context.Context, ent.Mutation) (ent.Value, error) {
			return nil, errors.New("注入发件箱失败")
		})
	})
	tx, err := db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tx.Incident.UpdateOneID(inc.ID).SetStatus("closed").ExecX(ctx)
	if err = Record(ctx, tx, inc.ID, StatusChanged, Origin{Kind: "system"}, "open"); err == nil {
		t.Fatal("未返回发件箱故障")
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	row := db.Incident.GetX(ctx, inc.ID)
	if row.Status != "open" || row.IntegrationRevision != 0 {
		t.Fatal("发件箱失败遗留状态")
	}
}
