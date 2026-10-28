//go:build integration

package intel

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"openxdr/server/ent/intel"
	"openxdr/server/internal/testdb"
)

// 同步落库、手工情报不被覆盖、关掉的源立即清掉、拉取失败保留旧条目并记下原因。
func TestFeedsSync(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	var broken, truncated atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if truncated.Load() {
			w.Header().Set("Content-Length", "10000")
			_, _ = w.Write([]byte("8.8.8.8\n"))
			return
		}
		if broken.Load() {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		http.ServeFile(w, r, "testdata"+r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	saved := Catalog
	t.Cleanup(func() { Catalog = saved })
	Catalog = []Feed{
		{ID: "feodo", URL: srv.URL + "/feodo.txt", Severity: 5, parse: parseList},
		{ID: "threatfox", URL: srv.URL + "/threatfox.csv", Severity: 4, parse: parseThreatFox},
	}

	// 手工录入的同值情报优先
	client.Intel.Create().SetKind("ip").SetValue("162.243.103.246").SetSource("manual").SetSeverity(2).SaveX(ctx)

	f := &Feeds{DB: db, Client: client, Interval: time.Hour}
	if err := f.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	feodo := client.Intel.Query().Where(intel.SourceEQ("feed:feodo")).CountX(ctx)
	if feodo != 4 {
		t.Errorf("Feodo 5 条里 1 条已有手工情报，应落库 4 条，实际 %d", feodo)
	}
	manual := client.Intel.Query().Where(intel.ValueEQ("162.243.103.246")).OnlyX(ctx)
	if manual.Source != "manual" || manual.Severity != 2 {
		t.Errorf("手工情报不应被订阅覆盖：%+v", manual)
	}
	row := client.Intel.Query().Where(intel.ValueEQ("152.42.212.170")).OnlyX(ctx)
	if row.Source != "feed:threatfox" || row.Note == nil || *row.Note != "ThreatFox：Jackskid" || row.ExpiresAt == nil {
		t.Errorf("订阅条目应带来源、备注与有效期：%+v", row)
	}
	st := f.Status(ctx)
	if st["feodo"].Count != 5 || st["feodo"].SyncedAt == nil || st["feodo"].Error != "" {
		t.Errorf("应记录同步结果：%+v", st["feodo"])
	}

	lastSuccess := *st["feodo"].SyncedAt
	if st["feodo"].AttemptedAt == nil || !st["feodo"].AttemptedAt.Equal(lastSuccess) {
		t.Fatal("首次成功的尝试与成功时间应一致")
	}

	// 拉取失败：旧条目保留，记下原因
	broken.Store(true)
	if err := f.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if n := client.Intel.Query().Where(intel.SourceEQ("feed:feodo")).CountX(ctx); n != 4 {
		t.Errorf("拉取失败不应丢旧条目，剩 %d", n)
	}
	if st := f.Status(ctx)["feodo"]; st.Error == "" || st.Count != 5 {
		t.Errorf("应记下失败原因并保留上次条目数：%+v", st)
	}

	failed := f.Status(ctx)["feodo"]
	if failed.SyncedAt == nil || !failed.SyncedAt.Equal(lastSuccess) || failed.AttemptedAt == nil || failed.AttemptedAt.Equal(lastSuccess) {
		t.Fatalf("失败只能刷新尝试时间，不得伪造成功时间：%+v", failed)
	}
	broken.Store(false)
	if err := f.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	recovered := f.Status(ctx)["feodo"]
	if recovered.Error != "" || recovered.SyncedAt == nil || recovered.AttemptedAt == nil || !recovered.SyncedAt.Equal(*recovered.AttemptedAt) || recovered.SyncedAt.Equal(*failed.AttemptedAt) {
		t.Fatalf("恢复后必须清除错误并更新成功时间：%+v", recovered)
	}

	// 读到一条合法 IOC 后断流，也不能更新情报或续期旧记录。
	before := client.Intel.Query().Where(intel.ValueEQ("152.42.212.170")).OnlyX(ctx)
	truncated.Store(true)
	if err := f.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if client.Intel.Query().Where(intel.ValueEQ("8.8.8.8")).ExistX(ctx) {
		t.Fatal("断流响应的部分情报不应入库")
	}
	after := client.Intel.Query().Where(intel.ValueEQ("152.42.212.170")).OnlyX(ctx)
	if !after.ExpiresAt.Equal(*before.ExpiresAt) {
		t.Fatal("断流不应刷新旧情报有效期")
	}
	if st := f.Status(ctx)["feodo"]; st.Error == "" || !st.SyncedAt.Equal(*recovered.SyncedAt) {
		t.Fatalf("断流不能标记成功：%+v", st)
	}
	truncated.Store(false)

	// 关掉 threatfox：立即清掉
	broken.Store(false)
	if err := f.SaveSettings(ctx, FeedSettings{Enabled: []string{"feodo"}}); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if n := client.Intel.Query().Where(intel.SourceEQ("feed:threatfox")).CountX(ctx); n != 0 {
		t.Errorf("关掉的源应清空，剩 %d", n)
	}
	if _, ok := f.Status(ctx)["threatfox"]; ok {
		t.Error("关掉的源不应再有状态")
	}
	if err := f.SaveSettings(ctx, FeedSettings{Enabled: []string{"nope"}}); err == nil {
		t.Error("未知源 ID 应拒绝")
	}
}

func TestFeedStatusLegacyTimes(t *testing.T) {
	ctx, client := testdb.New(t)
	f := &Feeds{Client: client}
	at := time.Now().UTC().Truncate(time.Second)
	for _, failed := range []bool{false, true} {
		st := FeedStatus{SyncedAt: &at, Count: 5}
		if failed {
			st.Error = "情报源返回 410"
		}
		if err := f.putSetting(ctx, feedStatusKey, map[string]FeedStatus{"feodo": st}); err != nil {
			t.Fatal(err)
		}
		got := f.Status(ctx)["feodo"]
		if got.AttemptedAt == nil || !got.AttemptedAt.Equal(at) || got.Count != 5 {
			t.Fatalf("旧记录的尝试时间和计数必须保留：%+v", got)
		}
		if failed && got.SyncedAt != nil {
			t.Fatal("旧版失败时间不能当作成功时间")
		}
		if !failed && (got.SyncedAt == nil || !got.SyncedAt.Equal(at)) {
			t.Fatal("旧版成功时间必须保留")
		}
	}
}
