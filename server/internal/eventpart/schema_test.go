package eventpart

import (
	"strings"
	"testing"
	"time"

	atlas "ariga.io/atlas/sql/schema"

	"openxdr/server/ent/migrate"
)

// events 不归 ent 迁移管，ent schema 加了列这里必须同步，否则新列永远建不出来。
func TestColumnsMatchEntSchema(t *testing.T) {
	var names []string
	for _, c := range migrate.EventsColumns {
		names = append(names, c.Name)
	}
	if got := strings.Join(names, ", "); got != Columns {
		t.Fatalf("ent 事件列 %q 与分区表列 %q 不一致", got, Columns)
	}
	for _, c := range migrate.EventsColumns {
		if !strings.Contains(columnDDL, c.Name+" ") {
			t.Fatalf("分区表 DDL 缺列 %s", c.Name)
		}
	}
	for _, idx := range migrate.EventsTable.Indexes {
		found := false
		for _, own := range indexes {
			found = found || own.name == idx.Name
		}
		if !found {
			t.Fatalf("ent 索引 %s 未在分区表上建", idx.Name)
		}
	}
}

func TestHideEventsDropsTableAndReferences(t *testing.T) {
	events := atlas.NewTable(Parent)
	assets := atlas.NewTable("assets")
	alerts := atlas.NewTable("alerts")
	alerts.ForeignKeys = []*atlas.ForeignKey{{Symbol: "alerts_events_alerts", RefTable: events}, {Symbol: "alerts_assets_alerts", RefTable: assets}}
	s := &atlas.Schema{Tables: []*atlas.Table{assets, events, alerts}}
	hideEvents(s)
	if len(s.Tables) != 2 || s.Tables[0] != assets || s.Tables[1] != alerts {
		t.Fatalf("events 未从比对中移除: %v", s.Tables)
	}
	if len(alerts.ForeignKeys) != 1 || alerts.ForeignKeys[0].Symbol != "alerts_assets_alerts" {
		t.Fatalf("指向 events 的外键未移除: %v", alerts.ForeignKeys)
	}
}

func TestPartitionNames(t *testing.T) {
	day := time.Date(2026, 10, 20, 15, 4, 5, 0, time.FixedZone("CST", 8*3600))
	if got := DailyName(dayStart(day)); got != "events_p20261020" {
		t.Fatal(got)
	}
	if got := ArchiveName(monthStart(day)); got != "events_a202610" {
		t.Fatal(got)
	}
	// 东八区 2026-10-21 03:00 仍是 UTC 20 日
	if got := dayStart(time.Date(2026, 10, 21, 3, 0, 0, 0, time.FixedZone("CST", 8*3600))); !got.Equal(time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)) {
		t.Fatal(got)
	}
	if got := literal(time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)); got != "'2026-10-20T00:00:00Z'" {
		t.Fatal(got)
	}
}

func TestIndexMethod(t *testing.T) {
	m, err := indexMethod("CREATE INDEX events_raw_trgm ON ONLY public.events USING gin (((raw)::text) gin_trgm_ops)")
	if err != nil || m != "gin (((raw)::text) gin_trgm_ops)" {
		t.Fatal(m, err)
	}
	if _, err := indexMethod("CREATE UNIQUE INDEX x ON public.events USING btree (id)"); err == nil {
		t.Fatal("唯一索引在分区表上不含 ts 建不起来，必须拒绝")
	}
}
