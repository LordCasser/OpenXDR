//go:build integration

package eventsearch

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
)

func open(t *testing.T) (context.Context, *ent.Client, *sql.DB) {
	t.Helper()
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, name := range []string{oldIndex, newIndex} {
		db.ExecContext(ctx, "DROP INDEX IF EXISTS "+name)
	}
	return ctx, client, db
}

func hits(t *testing.T, ctx context.Context, client *ent.Client, kw string) int {
	t.Helper()
	n, err := client.Event.Query().Where(Keyword(kw)).Count(ctx)
	if err != nil {
		t.Fatalf("检索 %q 失败: %v", kw, err)
	}
	return n
}

const raw = `{"process": {"pid": 720634, "uid": "5000508e-c623-4ea9-b9d2-4bbb2dcc5eee",
  "file": {"path": "/usr/bin/curl", "sha256": "43b8d2d049183e9ebc409c86b89150b5a4a68fa19fe1815b16bed5561921a9c3"},
  "cmd_line": "curl http://Evil.example:4444/x 100%_done"}, "activity_id": 1}`

// 新库启动即建值索引：值照常搜得到（大小写不敏感、% _ 是字面量），UUID 与哈希回退全文不漏，
// 字段名不再命中。
func TestEnsureBuildsValueIndex(t *testing.T) {
	ctx, client, db := open(t)
	client.Event.Create().SetTs(time.Now()).SetClassUID(1007).SetSource("agent").SetRaw(json.RawMessage(raw)).SaveX(ctx)

	Ensure(ctx, db)
	if ok, err := validIndex(ctx, db, newIndex); err != nil || !ok || !byValue.Load() {
		t.Fatalf("新库应建好并启用 %s: valid=%v err=%v byValue=%v", newIndex, ok, err, byValue.Load())
	}
	for kw, want := range map[string]int{
		"evil.EXAMPLE": 1, "/usr/bin/curl": 1, "4444": 1, "720634": 1, "100%_done": 1, "100%x": 0,
		"43b8d2d049183e9e": 1, "5000508e-c623": 1, "cmd_line": 0, "nothing-here": 0,
	} {
		if got := hits(t, ctx, client, kw); got != want {
			t.Errorf("检索 %q 命中 %d 条, want %d", kw, got, want)
		}
	}
}

// 有旧索引的库启动不现建新索引（大表上会挡住写入几个小时），仍按 raw::text 匹配；
// 管理员在线建好新索引后重启即切换。
func TestEnsureKeepsOldIndex(t *testing.T) {
	ctx, client, db := open(t)
	client.Event.Create().SetTs(time.Now()).SetClassUID(1007).SetSource("agent").SetRaw(json.RawMessage(raw)).SaveX(ctx)
	if _, err := db.ExecContext(ctx, "CREATE EXTENSION IF NOT EXISTS pg_trgm"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "CREATE INDEX "+oldIndex+" ON events USING gin ((raw::text) gin_trgm_ops)"); err != nil {
		t.Fatal(err)
	}

	Ensure(ctx, db)
	if ok, _ := exists(ctx, db, newIndex); ok || byValue.Load() {
		t.Fatalf("已有旧索引时不应现建 %s: exists=%v byValue=%v", newIndex, ok, byValue.Load())
	}
	if got := hits(t, ctx, client, "cmd_line"); got != 1 {
		t.Fatalf("旧口径按整个事件体匹配，字段名应命中: %d", got)
	}

	if _, err := db.ExecContext(ctx, "CREATE INDEX "+newIndex+" ON events USING gin (openxdr_event_search_text(raw) gin_trgm_ops)"); err != nil {
		t.Fatal(err)
	}
	Ensure(ctx, db)
	if !byValue.Load() || hits(t, ctx, client, "cmd_line") != 0 || hits(t, ctx, client, "evil.example") != 1 {
		t.Fatalf("新索引建好后应切到按值匹配: byValue=%v", byValue.Load())
	}
}
