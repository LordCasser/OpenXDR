//go:build integration

package janitor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/auditlog"
	"openxdr/server/internal/testdb"
)

// 只关"AI 判良性 + 级别低于高危 + 放够天数"的事件；高危、可疑、新事件、良性结论后又有新证据待重研判的都不碰，N=0 关闭。
func TestAutoCloseBenign(t *testing.T) {
	ctx, client := testdb.New(t)
	old := time.Now().AddDate(0, 0, -8)
	create := func(verdict string, severity int16, at time.Time) string {
		inc := client.Incident.Create().SetStatus("triaged").SetGraph(json.RawMessage(`{}`)).
			SetAiVerdict(json.RawMessage(`{"verdict":"` + verdict + `"}`)).SetCreatedAt(at).SaveX(ctx)
		client.Alert.Create().SetTs(at).SetRuleID("r").SetSeverity(severity).SetIncidentID(inc.ID).SaveX(ctx)
		return inc.ID.String()
	}
	lowOld := create("benign", 3, old)
	highOld := create("benign", 4, old)
	suspiciousOld := create("suspicious", 1, old)
	lowNew := create("benign", 1, time.Now())
	pending := create("benign", 2, old)
	client.Incident.UpdateOneID(uuid.MustParse(pending)).SetTriagedAt(old).SetEvidenceAt(time.Now()).ExecX(ctx)

	if n, err := (&AutoClose{DB: client, Days: 0}).sweep(ctx); err != nil || n != 0 {
		t.Fatalf("N=0 应关闭自动结案，得到 %d %v", n, err)
	}
	a := &AutoClose{DB: client, Days: 7}
	if n, err := a.sweep(ctx); err != nil || n != 1 {
		t.Fatalf("应只关 1 个，得到 %d %v", n, err)
	}
	// 重复执行（如两个节点先后跑）不再动已结案的
	if n, err := a.sweep(ctx); err != nil || n != 0 {
		t.Fatalf("重复执行应为空操作，得到 %d %v", n, err)
	}
	for _, inc := range client.Incident.Query().AllX(ctx) {
		switch inc.ID.String() {
		case lowOld:
			if inc.Status != "false_positive" || inc.ResolvedBy == nil || *inc.ResolvedBy != "system" || inc.ResolvedAt == nil ||
				inc.Resolution == nil || !strings.Contains(*inc.Resolution, "7 天无人处理") {
				t.Errorf("低危良性旧事件应自动结案：%+v", inc)
			}
		case highOld, suspiciousOld, lowNew, pending:
			if inc.Status != "triaged" || inc.ResolvedBy != nil {
				t.Errorf("%s 不该被结案：%+v", inc.ID, inc)
			}
		}
	}
	if n := client.AuditLog.Query().Where(auditlog.ActionEQ("incident_auto_closed")).CountX(ctx); n != 1 {
		t.Errorf("只有关了事件的那一轮才落审计，得到 %d 条", n)
	}
}
