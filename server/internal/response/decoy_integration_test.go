//go:build integration

package response

import (
	"encoding/json"
	"openxdr/server/ent/auditlog"
	"openxdr/server/internal/decoy"
	"openxdr/server/internal/testdb"
	"strings"
	"testing"
	"time"
)

func TestDecoyObservationCannotAutoIsolate(t *testing.T) {
	ctx, db := testdb.New(t)
	host := db.Asset.Create().SetHostname("decoy-host").SaveX(ctx)
	incident := db.Incident.Create().SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	db.Alert.Create().SetTs(time.Now()).SetRuleID(decoy.ObservationRulePrefix + "marker_used").SetAssetID(host.ID).SetIncidentID(incident.ID).SetSeverity(3).ExecX(ctx)
	auto := &Auto{Hub: &Hub{DB: db}, MinConfidence: 90}
	auto.React(ctx, incident.ID, json.RawMessage(`{"verdict":"malicious","confidence":100}`))
	if db.Command.Query().CountX(ctx) != 0 {
		t.Fatal("仅诱饵观察触发处置")
	}
	entry := db.AuditLog.Query().Where(auditlog.ActionEQ("auto_response_skipped")).OnlyX(ctx)
	if entry.Detail == nil || !strings.Contains(*entry.Detail, "除诱饵观察外没有高危独立告警") {
		t.Fatal(entry.Detail)
	}
	// 另一个资产的独立告警不能解除本机的诱饵证据限制。
	other := db.Asset.Create().SetHostname("independent-host").SaveX(ctx)
	db.Alert.Create().SetTs(time.Now()).SetRuleID("independent-rule").SetAssetID(other.ID).SetIncidentID(incident.ID).SetSeverity(4).ExecX(ctx)
	auto.Exempt = map[string]bool{"independent-host": true}
	auto.React(ctx, incident.ID, json.RawMessage(`{"verdict":"malicious","confidence":100}`))
	if n := db.AuditLog.Query().Where(auditlog.ActionEQ("auto_response_skipped"), auditlog.DetailContains("decoy-host 除诱饵观察外")).CountX(ctx); n != 2 {
		t.Fatal("其他资产错误解除限制", n)
	}
	// 同主机并进来的低危噪声也不能解除限制。
	db.Alert.Create().SetTs(time.Now()).SetRuleID("noise-rule").SetAssetID(host.ID).SetIncidentID(incident.ID).SetSeverity(2).ExecX(ctx)
	auto.React(ctx, incident.ID, json.RawMessage(`{"verdict":"malicious","confidence":100}`))
	if n := db.AuditLog.Query().Where(auditlog.ActionEQ("auto_response_skipped"), auditlog.DetailContains("decoy-host 除诱饵观察外")).CountX(ctx); n != 3 {
		t.Fatal("低危噪声解除了诱饵限制", n)
	}
}
