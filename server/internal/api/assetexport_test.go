package api

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
)

func TestAssetExportFormats(t *testing.T) {
	now := time.Now().UTC()
	title := " =HYPERLINK(\"https://example.test\")"
	rows := []assetExportRow{{ID: uuid.New(), Hostname: title, IPAddrs: []string{"10.0.0.1", "::1"}, FirstSeen: now, LastSeen: now, HostState: "online"}, {Hostname: "中文,\"主机\"\n第二行"}}
	data, err := encodeAssetExport("csv", assetSelection{Mode: "filter"}, rows, now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
		t.Fatal("缺少 BOM")
	}
	parsed, err := csv.NewReader(bytes.NewReader(data[3:])).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 3 || parsed[1][1] != "'"+title || parsed[1][4] != "10.0.0.1;::1" || parsed[2][1] != rows[1].Hostname {
		t.Fatalf("CSV 内容错误: %#v", parsed)
	}
	data, err = encodeAssetExport("json", assetSelection{Mode: "filter"}, rows, now)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Items []assetExportRow `json:"items"`
		Count int              `json:"count"`
	}
	if err = json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Count != 2 || result.Items[0].Hostname != title {
		t.Fatal("JSON 必须保留原始字段")
	}
}

func TestCSVFormulaProtection(t *testing.T) {
	for _, s := range []string{"=1", "+1", "-1", "@SUM(A1)", "\ttext", "\rtext", "\ntext", "  =1", "\u2003@x"} {
		if csvSafe(s) != "'"+s {
			t.Errorf("未防护 %q", s)
		}
	}
	if csvSafe("普通主机") != "普通主机" {
		t.Fatal("修改了普通文本")
	}
}

func TestAssetExportSelection(t *testing.T) {
	id := uuid.New()
	valid := assetSelection{Mode: "ids", IDs: []uuid.UUID{id, id}}
	if err := valid.validate(); err != nil || len(valid.IDs) != 1 {
		t.Fatal("ID 未去重", err)
	}
	for _, s := range []assetSelection{{}, {Mode: "ids"}, {Mode: "ids", IDs: []uuid.UUID{id}, Q: "x"}, {Mode: "filter", IDs: []uuid.UUID{id}}, {Mode: "filter", GroupID: "bad"}} {
		if s.validate() == nil {
			t.Errorf("接受无效选择 %#v", s)
		}
	}
}

func TestExportedHostState(t *testing.T) {
	now := time.Now()
	sensor := now
	old := now.Add(-10 * time.Minute)
	id := uuid.New()
	for _, c := range []struct {
		a    ent.Asset
		want string
	}{
		{ent.Asset{LastSeen: time.Unix(0, 0)}, "imported"},
		{ent.Asset{LastSeen: old, SensorSeen: &sensor}, "online"},
		{ent.Asset{LastSeen: old, SensorSeen: &sensor, AgentID: &id}, "stale"},
		{ent.Asset{LastSeen: now, SilentSince: &old}, "silent"},
	} {
		if got := exportedHostState(&c.a, now); got != c.want {
			t.Errorf("got %s want %s", got, c.want)
		}
	}
}

func TestAssetExportSizeLimit(t *testing.T) {
	b := &exportBuffer{}
	if _, err := b.Write(bytes.Repeat([]byte("x"), assetExportBytes)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte("x")); err == nil || b.Len() != assetExportBytes {
		t.Fatal("大小限制失效")
	}
	rows := []assetExportRow{{Hostname: strings.Repeat("x", assetExportBytes)}}
	for _, format := range []string{"csv", "json"} {
		if _, err := encodeAssetExport(format, assetSelection{}, rows, time.Now()); err == nil {
			t.Errorf("%s 超限未拒绝", format)
		}
	}
}
