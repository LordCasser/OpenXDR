//go:build integration

package directory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"openxdr/server/internal/cluster"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/testdb"
)

type readerFunc func(context.Context) (Scan, error)

func (f readerFunc) ReadAccounts(ctx context.Context) (Scan, error) { return f(ctx) }

func TestDirectorySyncLifecycle(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	group := client.Group.Create().SetName("sync").SaveX(ctx)
	source := Source{ID: uuid.New(), GroupID: group.ID, Kind: "keycloak", Authority: "https://directory.invalid/realms/one"}
	if err := RegisterSource(ctx, db, source); err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Add(-time.Hour)
	scan := Scan{Source: source, StartedAt: start, FinishedAt: start.Add(time.Minute), Accounts: []Account{{ExternalID: "one", Username: "original"}}}
	read := readerFunc(func(context.Context) (Scan, error) { return scan, nil })
	run, err := SyncOnce(ctx, db, source, read)
	if err != nil || run.Status != "succeeded" || run.AccountCount != 1 || run.FinishedAt == nil {
		t.Fatalf("成功状态: %+v %v", run, err)
	}
	for _, test := range []struct {
		code   string
		reader readerFunc
	}{
		{"read_failed", func(context.Context) (Scan, error) { return scan, fmt.Errorf("secret-password") }},
		{"source_mismatch", func(context.Context) (Scan, error) { s := scan; s.Source.GroupID = uuid.New(); return s, nil }},
		{"invalid_result", func(context.Context) (Scan, error) { s := scan; s.Accounts = nil; return s, nil }},
		{"stale_scan", read},
	} {
		run, err := SyncOnce(ctx, db, source, test.reader)
		if !errors.Is(err, ErrSyncFailed) || run.Status != "failed" || run.ErrorCode != test.code || run.AccountCount != 0 {
			t.Fatalf("失败状态: %+v %v", run, err)
		}
	}
	// 取消后的失败记录使用独立短事务，仍应留下可核对状态。
	canceledCtx, cancel := context.WithCancel(ctx)
	run, err = SyncOnce(canceledCtx, db, source, readerFunc(func(context.Context) (Scan, error) { cancel(); return Scan{}, context.Canceled }))
	if !errors.Is(err, ErrSyncFailed) || run.ErrorCode != "canceled" {
		t.Fatalf("取消记录: %+v %v", run, err)
	}
	// 未登记或归组不一致时，不触发外部读取。
	wrong := source
	wrong.GroupID = uuid.New()
	_, err = SyncOnce(ctx, db, wrong, readerFunc(func(context.Context) (Scan, error) { t.Error("来源校验前读取目录"); return Scan{}, nil }))
	if !errors.Is(err, ErrSourceConflict) {
		t.Fatalf("来源错配: %v", err)
	}
	// 强制成功状态写入失败；账号更新与成功游标必须一起回滚。
	if _, err := db.ExecContext(ctx, `ALTER TABLE identity_directory_runs ADD CONSTRAINT test_sync_failure CHECK(status <> 'succeeded') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	scan.StartedAt = start.Add(2 * time.Minute)
	scan.FinishedAt = start.Add(3 * time.Minute)
	scan.Accounts[0].Username = "changed"
	run, err = SyncOnce(ctx, db, source, read)
	if _, dropErr := db.ExecContext(ctx, `ALTER TABLE identity_directory_runs DROP CONSTRAINT test_sync_failure`); dropErr != nil {
		t.Fatal(dropErr)
	}
	if !errors.Is(err, ErrSyncFailed) || run.ErrorCode != "persist_failed" {
		t.Fatalf("持久失败状态: %+v %v", run, err)
	}
	var name string
	var last time.Time
	if err := db.QueryRowContext(ctx, `SELECT a.username,s.last_started_at FROM identity_directory_accounts a JOIN identity_directory_sources s ON s.id=a.source_id WHERE s.id=$1`, source.ID).Scan(&name, &last); err != nil {
		t.Fatal(err)
	}
	if name != "original" || !last.Equal(start.Truncate(time.Microsecond)) {
		t.Fatal("失败同步改写账号或成功游标")
	}
	run, err = SyncOnce(ctx, db, source, read)
	if err != nil || run.Status != "succeeded" {
		t.Fatalf("恢复同步: %+v %v", run, err)
	}
	// 模拟提交成功但调用方认为失败；失败处理不得覆盖成功状态。
	confirmed, err := failRun(db, run, "persist_failed")
	if err != nil || confirmed.Status != "succeeded" || confirmed.ErrorCode != "" {
		t.Fatal("已提交成功被改成失败")
	}
}

func TestDirectoryWorkerPersistsReaderResults(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	group := client.Group.Create().SetName("worker").SaveX(ctx)
	reader := keycloakFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("first") == "0" {
			fmt.Fprint(w, `[{"id":"one","username":"account","enabled":true}]`)
		} else {
			fmt.Fprint(w, `[]`)
		}
	})
	reader.source.GroupID = group.ID
	jobs := []Job{{Source: reader.source, Reader: reader, Interval: time.Hour}}
	if err := RegisterJobs(ctx, db, jobs); err != nil {
		t.Fatal(err)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{}, 2)
	for range 2 {
		go func() {
			defer func() { done <- struct{}{} }()
			cluster.RunLeader(workerCtx, db, "test-directory-worker", func(ctx context.Context) { RunWorker(ctx, db, jobs) })
		}()
	}
	defer func() {
		cancel()
		for range 2 {
			select {
			case <-done:
			case <-time.After(7 * time.Second):
				t.Error("目录工作者未退出")
			}
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM identity_directory_runs WHERE source_id=$1 AND status='succeeded'`, reader.source.ID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("目录结果未提交")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM identity_directory_accounts WHERE source_id=$1 AND username='account' AND enabled=true`, reader.source.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("读取结果未入库")
	}
}
