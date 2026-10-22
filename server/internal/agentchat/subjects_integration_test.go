//go:build integration

package agentchat

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/command"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/response"
	"openxdr/server/internal/testdb"
)

func TestIncidentHandoffContextAndCommandAssociation(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("handoff").SaveX(ctx)
	other := db.Group.Create().SetName("other").SaveX(ctx)
	host := db.Asset.Create().SetHostname("host").SetGroupID(group.ID).SaveX(ctx)
	unrelated := db.Asset.Create().SetHostname("unrelated").SetGroupID(group.ID).SaveX(ctx)
	inc := db.Incident.Create().SetGraph(json.RawMessage(`{}`)).SetEvidenceAt(time.Now()).
		SetClosureProposal(&schema.ClosureProposal{Status: "closed", Note: "复查通过", At: time.Now()}).SaveX(ctx)
	for i := 0; i < 11; i++ {
		db.Alert.Create().SetTs(time.Now()).SetRuleID("r").SetSeverity(3).SetAssetID(host.ID).SetIncidentID(inc.ID).SaveX(ctx)
	}
	cmd := db.Command.Create().SetAssetID(host.ID).SetIncidentID(inc.ID).SetKind("exec").SetStatus("unknown").SaveX(ctx)
	session := &ent.AgentSession{ID: uuid.New(), GroupID: group.ID, Subjects: []string{"incident:" + inc.ID.String()}}
	s := &Service{DB: db}
	names := map[uuid.UUID]string{host.ID: host.Hostname}
	rows, err := s.subjectsFor(ctx, session, names)
	if err != nil || len(rows) != 1 {
		t.Fatalf("交接失败: %v %v", rows, err)
	}
	row := rows[0]
	receipts := row["recent_commands"].([]map[string]any)
	if row["alert_count"] != 11 || row["alerts_truncated"] != true || len(row["alerts"].([]subjectAlert)) != 10 ||
		len(receipts) != 1 || receipts[0]["id"] != cmd.ID || receipts[0]["status"] != "unknown" || row["closure_proposal"] == nil || row["evidence_at"] == nil {
		t.Fatalf("交接缺少最新证据、截断提示或未知回执: %v", row)
	}
	actor := db.User.Create().SetUsername("handoff-admin").SetRole("admin").SetPasswordHash("unused").SaveX(ctx)
	persisted := db.AgentSession.Create().SetKind("chat").SetInitiator(actor.Username).SetGroupID(group.ID).SetModel("test").SetSubjects(session.Subjects).SaveX(ctx)
	db.Asset.UpdateOneID(host.ID).SetAgentID(uuid.New()).ExecX(ctx)
	s.Gate = &commandgate.Gate{DB: db, Hub: response.NewHub(db, true)}
	// 没有接入真实 agent：验证下发记录关联与失败回执，不运行主机命令。
	if _, err := s.tool(ctx, persisted, commandgate.Request{UserID: actor.ID}, "exec", []byte(`{"host":"`+host.ID.String()+`","cmd":"id"}`)); err != nil {
		t.Fatal(err)
	}
	linked := db.Command.Query().Where(command.IDNEQ(cmd.ID)).OnlyX(ctx)
	if linked.IncidentID == nil || *linked.IncidentID != inc.ID || linked.Status != "failed" {
		t.Fatalf("工具下发未保留事件归属与真实回执: %+v", linked)
	}
	id, err := s.commandIncident(ctx, session, host.ID)
	if err != nil || id == nil || *id != inc.ID {
		t.Fatalf("唯一事件未关联: %v %v", id, err)
	}
	if id, err = s.commandIncident(ctx, session, unrelated.ID); err != nil || id != nil {
		t.Fatalf("无关主机不能关联: %v %v", id, err)
	}
	another := db.Incident.Create().SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	db.Alert.Create().SetTs(time.Now()).SetRuleID("other").SetSeverity(3).SetAssetID(host.ID).SetIncidentID(another.ID).SaveX(ctx)
	session.Subjects = append(session.Subjects, "incident:"+another.ID.String())
	if id, err = s.commandIncident(ctx, session, host.ID); err != nil || id != nil {
		t.Fatalf("多个事件不能猜归属: %v %v", id, err)
	}
	session.Subjects = session.Subjects[:1]
	session.Subjects = append(session.Subjects, "finding:"+uuid.NewString())
	if id, err = s.commandIncident(ctx, session, host.ID); err != nil || id != nil {
		t.Fatal("混合待办会话不能猜测指令用于事件")
	}
	session.Subjects = session.Subjects[:1]
	db.Asset.UpdateOneID(host.ID).SetGroupID(other.ID).ExecX(ctx)
	if rows, err = s.subjectsFor(ctx, session, names); err != nil || len(rows) != 0 {
		t.Fatalf("转组后泄漏旧交接: %v %v", rows, err)
	}
	if id, err = s.commandIncident(ctx, session, host.ID); err != nil || id != nil {
		t.Fatalf("转组后仍关联: %v %v", id, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.subjectsFor(ctx, session, names); err == nil {
		t.Fatal("数据库错误被当成对象缺失吞掉")
	}
}

func TestFindingHandoffUsesCurrentGroupNotRosterLimit(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("finding-handoff").SaveX(ctx)
	other := db.Group.Create().SetName("other").SaveX(ctx)
	host := db.Asset.Create().SetHostname("beyond-roster").SetGroupID(group.ID).SaveX(ctx)
	item := db.Finding.Create().SetGroupID(group.ID).SetAssetID(host.ID).SetKey("service").SetTitle("待复查").SaveX(ctx)
	session := &ent.AgentSession{GroupID: group.ID, Subjects: []string{"finding:" + item.ID.String()}}
	s := &Service{DB: db}
	if rows, err := s.subjectsFor(ctx, session, map[uuid.UUID]string{}); err != nil || len(rows) != 1 {
		t.Fatalf("资产清单截断不能丢失授权待办: %v %v", rows, err)
	}
	db.Asset.UpdateOneID(host.ID).SetGroupID(other.ID).ExecX(ctx)
	if rows, err := s.subjectsFor(ctx, session, map[uuid.UUID]string{host.ID: host.Hostname}); err != nil || len(rows) != 0 {
		t.Fatalf("转组后泄漏待办: %v %v", rows, err)
	}
}
