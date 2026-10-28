//go:build integration

package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

// 列表默认不含订阅条目；订阅接口给出各源状态，保存开关即时同步。
func TestIntelFeedsAPI(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	client.Intel.Create().SetKind("ip").SetValue("1.1.1.1").SetSource("feed:feodo").SaveX(ctx)
	client.Intel.Create().SetKind("ip").SetValue("2.2.2.2").SetSource("manual").SaveX(ctx)

	lastSuccess := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	lastAttempt := lastSuccess.Add(time.Minute)
	value, err := json.Marshal(map[string]intel.FeedStatus{"feodo": {
		SyncedAt: &lastSuccess, AttemptedAt: &lastAttempt, Count: 1, Error: "情报源返回 410",
	}})
	if err != nil {
		t.Fatal(err)
	}
	client.Setting.Create().SetID("intel_feed_status").SetValue(value).SaveX(ctx)
	feeds := &intel.Feeds{DB: db, Client: client, Interval: time.Hour, HTTP: &http.Client{Transport: failing{}}}
	ts := httptest.NewServer(asAdmin(IntelFeeds(client, feeds)))
	t.Cleanup(ts.Close)

	var got struct {
		Feeds []struct {
			ID          string
			Enabled     bool
			Count       int
			Error       string
			SyncedAt    *time.Time
			AttemptedAt *time.Time
		}
		IntervalHours int
	}
	resp, err := http.Get(ts.URL + "/api/intel/feeds")
	if err != nil || json.NewDecoder(resp.Body).Decode(&got) != nil {
		t.Fatalf("读取订阅失败：%v", err)
	}
	if len(got.Feeds) != len(intel.Catalog) || !got.Feeds[0].Enabled || got.Feeds[0].Count != 1 || got.IntervalHours != 1 {
		t.Fatalf("未保存过时内置源应全开并统计条目：%+v", got)
	}

	if got.Feeds[0].SyncedAt == nil || !got.Feeds[0].SyncedAt.Equal(lastSuccess) || got.Feeds[0].AttemptedAt == nil || !got.Feeds[0].AttemptedAt.Equal(lastAttempt) {
		t.Fatalf("接口必须分别返回成功与尝试时间：%+v", got.Feeds[0])
	}

	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/intel/feeds", bytes.NewBufferString(`{"enabled":[]}`))
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("保存开关失败：%v %v", err, resp.Status)
	}
	if n := client.Intel.Query().CountX(ctx); n != 1 {
		t.Errorf("全部关掉后应只剩手工情报，实际 %d 条", n)
	}

	list := httptest.NewServer(asAdmin(Handler(client, loadRules(t), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)))
	t.Cleanup(list.Close)
	client.Intel.Create().SetKind("ip").SetValue("3.3.3.3").SetSource("feed:threatfox").SaveX(ctx)
	var rows []struct{ Value string }
	resp, _ = http.Get(list.URL + "/api/intel")
	_ = json.NewDecoder(resp.Body).Decode(&rows)
	if len(rows) != 1 || rows[0].Value != "2.2.2.2" {
		t.Errorf("情报列表不应包含订阅条目：%+v", rows)
	}
}

type failing struct{}

func (failing) RoundTrip(*http.Request) (*http.Response, error) { return nil, http.ErrHandlerTimeout }
