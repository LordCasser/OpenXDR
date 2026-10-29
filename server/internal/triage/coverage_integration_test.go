//go:build integration

package triage

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"openxdr/server/internal/testdb"
)

func TestInvestigationCoverage(t *testing.T) {
	ctx, db := testdb.New(t)
	e := &Engine{DB: db}
	now := time.Now()
	for i := 0; i < 16; i++ {
		db.Event.Create().SetTs(now.Add(-time.Duration(i) * time.Second)).SetClassUID(4001).SetSource("agent").SetRaw(json.RawMessage(`{"message":"coverage-test"}`)).SaveX(ctx)
	}
	out, err := e.toolQueryEvents(ctx, `{"keyword":"coverage-test","hours":1}`)
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	if m["truncated"] != true || m["returned"] != 15 || m["from"] == nil || m["to"] == nil {
		t.Fatalf("覆盖信息错误：%v", m)
	}
	out, err = e.toolQueryEvents(ctx, `{"keyword":"not-found"}`)
	if err != nil {
		t.Fatal(err)
	}
	m = out.(map[string]any)
	if m["truncated"] != false || m["returned"] != 0 || m["coverage"] == "" {
		t.Fatal(m)
	}
	host := db.Asset.Create().SetHostname("coverage").SaveX(ctx)
	for i := 0; i < 21; i++ {
		db.Alert.Create().SetAssetID(host.ID).SetTs(now.Add(-time.Duration(i) * time.Second)).SetRuleID("test").SetSeverity(2).SaveX(ctx)
	}
	out, err = e.toolHostAlerts(ctx, fmt.Sprintf(`{"asset_id":%q}`, host.ID))
	if err != nil {
		t.Fatal(err)
	}
	if out.(map[string]any)["truncated"] != true {
		t.Fatal(out)
	}
	missing := uuid.New()
	out, err = e.toolProcessLineage(ctx, fmt.Sprintf(`{"process_guid":%q}`, missing))
	if err != nil {
		t.Fatal(err)
	}
	if out.(map[string]any)["missing_ancestor"] != true {
		t.Fatal(out)
	}
	// 断库必须成为查询失败，不能伪装成空血缘。
	db.Close()
	result := e.execTool(ctx, "process_lineage", fmt.Sprintf(`{"process_guid":%q}`, missing))
	if !strings.Contains(result, `"status":"error"`) {
		t.Fatal(result)
	}
}

func TestBriefTruncationUTF8(t *testing.T) {
	ctx, db := testdb.New(t)
	ev := db.Event.Create().SetTs(time.Now()).SetClassUID(4001).SetSource("agent").SetRaw(json.RawMessage(`{"message":"` + strings.Repeat("中文", 100) + `"}`)).SaveX(ctx)
	b := brief(ev)
	if !b.RawTruncated || !utf8.ValidString(b.Raw) {
		t.Fatal(b)
	}
}
