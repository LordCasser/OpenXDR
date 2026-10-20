//go:build integration

package response

import (
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"openxdr/server/internal/testdb"
	"os"
	"testing"
	"time"
)

func TestVerificationEvidenceAuditAndScope(t *testing.T) {
	ctx, c := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := EnsureVerificationSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	g := c.Group.Create().SetName("verify-a").SaveX(ctx)
	b := c.Group.Create().SetName("verify-b").SaveX(ctx)
	a := c.Asset.Create().SetHostname("verify-host").SetGroupID(g.ID).SaveX(ctx)
	other := c.Asset.Create().SetHostname("other-host").SetGroupID(g.ID).SaveX(ctx)
	u := c.User.Create().SetUsername("reviewer").SetPasswordHash("unused").SetRole("analyst").SaveX(ctx)
	m := c.GroupMember.Create().SetGroupID(g.ID).SetUserID(u.ID).SetRole("analyst").SaveX(ctx)
	admin := c.User.Create().SetUsername("verify-admin").SetPasswordHash("unused").SetRole("admin").SaveX(ctx)
	issued := time.Now().Add(-time.Hour)
	cmd := c.Command.Create().SetAssetID(a.ID).SetKind("isolate_host").SetStatus("unknown").SetCreatedAt(issued).SaveX(ctx)
	event := func(asset uuid.UUID, ts time.Time) uuid.UUID {
		return c.Event.Create().SetAssetID(asset).SetTs(ts).SetSource("agent").SetClassUID(4001).SetRaw(json.RawMessage(`{"connection":"test-evidence"}`)).SaveX(ctx).ID
	}
	good := event(a.ID, issued.Add(time.Minute))
	in := VerificationInput{Outcome: "inconclusive", Expected: "隔离后的策略生效", Observed: "连接日志不足以判断策略效果", EventIDs: []uuid.UUID{good}}
	v, err := RecordVerification(ctx, db, u.ID, cmd.ID, "10.0.0.8", in)
	if err != nil {
		t.Fatal(err)
	}
	if v.Reviewer != u.Username || v.CommandStatus != "unknown" || len(v.Evidence) != 1 || v.GroupID == nil || *v.GroupID != g.ID {
		t.Fatalf("字段丢失: %+v", v)
	}
	if got := c.Command.GetX(ctx, cmd.ID); got.Status != "unknown" || got.CompletedAt != nil {
		t.Fatal("复核覆盖执行回执")
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='command_verification_recorded' AND target=$1 AND remote_addr='10.0.0.8'`, cmd.ID.String()).Scan(&count); err != nil || count != 1 {
		t.Fatalf("审计缺失: %d %v", count, err)
	}
	for _, bad := range []uuid.UUID{uuid.New(), event(other.ID, issued.Add(time.Minute)), event(a.ID, issued.Add(-time.Minute)), event(a.ID, time.Now().Add(time.Hour))} {
		x := in
		x.EventIDs = []uuid.UUID{bad}
		if _, err := RecordVerification(ctx, db, u.ID, cmd.ID, "10.0.0.8", x); !errors.Is(err, ErrVerificationInput) {
			t.Fatalf("接受无效证据: %v", err)
		}
	}
	c.Event.DeleteOneID(good).ExecX(ctx)
	check := func(user uuid.UUID, want int) []Verification {
		t.Helper()
		items, err := ListVerifications(ctx, db, user, cmd.ID)
		if err != nil || len(items) != want {
			t.Fatalf("列表 %d/%d: %v", len(items), want, err)
		}
		return items
	}
	if items := check(u.ID, 1); len(items[0].Evidence) != 1 || len(items[0].Evidence[0].Raw) != 0 {
		t.Fatal("列表应保留证据元数据且不展开原文")
	}
	empty := VerificationInput{Outcome: "inconclusive", Expected: "check", Observed: "unknown"}
	var retained string
	if err := db.QueryRow(`SELECT evidence->0->'raw'->>'connection' FROM command_verifications WHERE id=$1`, v.ID).Scan(&retained); err != nil || retained != "test-evidence" {
		t.Fatalf("证据快照丢失: %v", err)
	}

	detail, err := GetVerification(ctx, db, u.ID, cmd.ID, v.ID)
	if err != nil || len(detail.Evidence) != 1 || string(detail.Evidence[0].Raw) == "" {
		t.Fatalf("授权证据原文读取失败: %v", err)
	}
	if _, err := GetVerification(ctx, db, u.ID, uuid.New(), v.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("跨指令引用复核")
	}
	if _, err := GetVerification(ctx, db, u.ID, cmd.ID, uuid.New()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("不存在复核未拒绝")
	}
	c.GroupMember.UpdateOne(m).SetRole("viewer").ExecX(ctx)
	if _, err := RecordVerification(ctx, db, u.ID, cmd.ID, "10.0.0.8", empty); !errors.Is(err, ErrVerificationScope) {
		t.Fatal("viewer 写入")
	}
	c.Asset.UpdateOneID(a.ID).SetGroupID(b.ID).ExecX(ctx)
	check(u.ID, 0)
	if _, err := GetVerification(ctx, db, u.ID, cmd.ID, v.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("组外证据原文泄露")
	}
	c.GroupMember.DeleteOne(m).ExecX(ctx)
	c.GroupMember.Create().SetGroupID(b.ID).SetUserID(u.ID).SetRole("analyst").SaveX(ctx)
	check(u.ID, 0)
	if _, err := GetVerification(ctx, db, u.ID, cmd.ID, v.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("组外证据原文泄露")
	}
	check(admin.ID, 1)
	if _, err := GetVerification(ctx, db, admin.ID, cmd.ID, v.ID); err != nil {
		t.Fatalf("管理员无法读取原文: %v", err)
	}
	_, err = db.Exec(`ALTER TABLE audit_logs ADD CONSTRAINT reject_verification_test CHECK (action <> 'command_verification_recorded') NOT VALID`)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec(`ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS reject_verification_test`) })
	if _, err := RecordVerification(ctx, db, u.ID, cmd.ID, "10.0.0.8", empty); err == nil {
		t.Fatal("审计失败未阻断")
	}
	check(admin.ID, 1)
	if _, err := GetVerification(ctx, db, admin.ID, cmd.ID, v.ID); err != nil {
		t.Fatalf("管理员无法读取原文: %v", err)
	}
	if _, err := db.Exec(`ALTER TABLE audit_logs DROP CONSTRAINT reject_verification_test`); err != nil {
		t.Fatal(err)
	}
	c.Asset.UpdateOneID(a.ID).ClearGroupID().ExecX(ctx)
	if _, err := RecordVerification(ctx, db, u.ID, cmd.ID, "10.0.0.8", empty); !errors.Is(err, ErrVerificationScope) {
		t.Fatal("未分组越权")
	}
	if _, err := RecordVerification(ctx, db, admin.ID, cmd.ID, "10.0.0.8", empty); err != nil {
		t.Fatal(err)
	}
}
