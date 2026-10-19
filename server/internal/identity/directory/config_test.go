package directory

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDirectoryConfig(t *testing.T) {
	for _, kind := range []string{"keycloak", "entra", "ad", "ldap"} {
		config := sourceConfig{ID: uuid.New(), GroupID: uuid.New(), Kind: kind, URL: "https://directory.invalid", IntervalSeconds: 300}
		switch kind {
		case "keycloak":
			config.Realm = "one"
			config.TokenEnv = "DIRECTORY_TOKEN"
		case "entra":
			config.TenantID = uuid.New()
			config.TokenEnv = "DIRECTORY_TOKEN"
		default:
			config.URL = "ldaps://directory.invalid"
			config.BaseDN = "dc=example,dc=invalid"
			config.BindUserEnv = "DIRECTORY_USER"
			config.BindPasswordEnv = "DIRECTORY_PASSWORD"
		}
		data, _ := json.Marshal([]sourceConfig{config})
		jobs, err := LoadConfig(string(data), func(string) string { return "secret" })
		if err != nil || len(jobs) != 1 || jobs[0].Source.ID != config.ID || jobs[0].Source.GroupID != config.GroupID || jobs[0].Interval != 5*time.Minute {
			t.Fatalf("%s: %v", kind, err)
		}
		if strings.Contains(jobs[0].Source.Authority, "secret") {
			t.Fatal("来源包含凭据")
		}
	}
}

func TestDirectoryConfigRejectsAmbiguity(t *testing.T) {
	base := sourceConfig{ID: uuid.New(), GroupID: uuid.New(), Kind: "keycloak", URL: "https://directory.invalid", Realm: "one", TokenEnv: "TOKEN"}
	for _, mutate := range []func(*sourceConfig){
		func(c *sourceConfig) { c.IntervalSeconds = 1 }, func(c *sourceConfig) { c.IntervalSeconds = 86401 }, func(c *sourceConfig) { c.TokenEnv = "secret-value" },
		func(c *sourceConfig) { c.BindUserEnv = "USER" }, func(c *sourceConfig) { c.TenantID = uuid.New() }, func(c *sourceConfig) { c.CAEnv = "CA" }, func(c *sourceConfig) { c.ID = uuid.Nil },
	} {
		config := base
		mutate(&config)
		data, _ := json.Marshal([]sourceConfig{config})
		if _, err := LoadConfig(string(data), func(string) string { return "secret-value" }); err == nil || strings.Contains(err.Error(), "secret-value") {
			t.Fatal("无效配置获准或泄露值")
		}
	}
	data, _ := json.Marshal([]sourceConfig{base, base})
	if _, err := LoadConfig(string(data), func(string) string { return "secret" }); err == nil {
		t.Fatal("重复来源获准")
	}
	data, _ = json.Marshal([]sourceConfig{base})
	if _, err := LoadConfig(string(data), func(string) string { return "" }); err == nil {
		t.Fatal("缺失凭据获准")
	}
	for _, raw := range []string{`null`, `{}`, `[{"password":"secret-value"}]`, `[] []`, strings.Repeat(" ", 65537) + "[]"} {
		if _, err := LoadConfig(raw, func(string) string { return "" }); err == nil || strings.Contains(err.Error(), "secret-value") {
			t.Fatal("坏 JSON 获准或泄露")
		}
	}
	for _, raw := range []string{"", "  ", "[]"} {
		jobs, err := LoadConfig(raw, func(string) string { return "" })
		if err != nil || len(jobs) != 0 {
			t.Fatal("空配置未关闭同步")
		}
	}
}

func TestDirectoryWorkersBoundConcurrencyAndStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jobs := make([]Job, 8)
	for i := range jobs {
		jobs[i].Interval = time.Hour
	}
	started := make(chan struct{}, 8)
	done := make(chan struct{})
	var active, peak atomic.Int32
	go func() {
		defer close(done)
		runJobs(ctx, jobs, func(ctx context.Context, _ Job) {
			n := active.Add(1)
			defer active.Add(-1)
			for old := peak.Load(); n > old; old = peak.Load() {
				if peak.CompareAndSwap(old, n) {
					break
				}
			}
			started <- struct{}{}
			<-ctx.Done()
		})
	}()
	for range 4 {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("未启动四个工作者")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("取消未退出")
	}
	if peak.Load() != 4 || active.Load() != 0 {
		t.Fatal("并发上限或退出错误")
	}
}

func TestDirectoryWorkerWaitsBetweenAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	var first time.Time
	runJobs(ctx, []Job{{Interval: 20 * time.Millisecond}}, func(context.Context, Job) {
		calls++
		if calls == 1 {
			first = time.Now()
			return
		}
		if time.Since(first) < 20*time.Millisecond {
			t.Error("未等待完整周期")
		}
		cancel()
	})
	if calls != 2 {
		t.Fatal("重复调度错误")
	}
}
