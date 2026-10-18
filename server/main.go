package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"

	"openxdr/server/ent"
	"openxdr/server/internal/agentchat"
	"openxdr/server/internal/aiconf"
	"openxdr/server/internal/api"
	"openxdr/server/internal/assetmap"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/cluster"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/correlate"
	"openxdr/server/internal/enroll"
	"openxdr/server/internal/eventbus"
	"openxdr/server/internal/grpcsvc"
	"openxdr/server/internal/hostimport"
	"openxdr/server/internal/ingest"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/janitor"
	"openxdr/server/internal/liveness"
	"openxdr/server/internal/notify"
	"openxdr/server/internal/piruntime"
	"openxdr/server/internal/queryrole"
	"openxdr/server/internal/realip"
	"openxdr/server/internal/report"
	"openxdr/server/internal/response"
	"openxdr/server/internal/schedule"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/syslog"
	"openxdr/server/internal/telemetry"
	"openxdr/server/internal/triage"
	"openxdr/server/internal/ueba"
	"openxdr/server/pb"
)

func main() {
	configureLogging()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	dsn := getenv("DATABASE_URL", "postgres://openxdr:openxdr@localhost:5432/openxdr?sslmode=disable")
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		slog.Error("数据库连接失败", "err", err)
		os.Exit(1)
	}
	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	defer client.Close()
	if err := cluster.WithLock(ctx, db, "schema", func() error {
		if err := client.Schema.Create(ctx); err != nil {
			return err
		}
		ensureSearchIndex(ctx, db)
		// 旧版 AI 免审批名单换成高风险名单；放在 schema 锁里，多节点同时启动只迁一次
		if err := commandgate.MigrateAllowToDeny(ctx, client); err != nil {
			return err
		}
		if err := commandgate.UpgradeDefaults(ctx, client); err != nil {
			return err
		}
		return ingest.EnsureSchema(ctx, db)
	}); err != nil {
		slog.Error("集群处理状态初始化失败", "err", err)
		os.Exit(1)
	}

	suppressions := suppress.New(client, time.Duration(getenvInt("SUPPRESSION_RELOAD_SECONDS", 30))*time.Second)
	go suppressions.Run(ctx)

	intelStore := intel.New(client, time.Duration(getenvInt("INTEL_RELOAD_SECONDS", 30))*time.Second)
	go intelStore.Run(ctx)
	// 情报订阅：内置公开源，控制台开关，单活定时拉取；落库后由 intelStore 下个重载周期生效
	intelFeeds := &intel.Feeds{DB: db, Client: client, HTTP: &http.Client{},
		Interval: time.Duration(getenvInt("INTEL_FEED_INTERVAL_HOURS", 6)) * time.Hour}
	go cluster.RunLeader(ctx, db, "intel-feeds", intelFeeds.Run)

	rulesPath := getenv("RULES_PATH", "../rules")
	rules := sigma.LoadDir(rulesPath)
	if sec := getenvInt("RULES_RELOAD_SECONDS", 30); sec > 0 {
		go rules.Watch(ctx, rulesPath, time.Duration(sec)*time.Second)
	}

	correlator := &correlate.Engine{
		DB:            client,
		Rules:         rules,
		Window:        time.Duration(getenvInt("CORRELATE_WINDOW_MINUTES", 30)) * time.Minute,
		Interval:      time.Duration(getenvInt("CORRELATE_INTERVAL_SECONDS", 10)) * time.Second,
		MaxGraphNodes: getenvInt("CORRELATE_MAX_GRAPH_NODES", 500),
	}
	go cluster.RunLeader(ctx, db, "correlate", correlator.Run)

	// UEBA 首次出现：先学习后告警，学习期按资产从首次观测起算
	uebaEngine := &ueba.Engine{
		DB:             client,
		Suppress:       suppressions,
		LearningPeriod: time.Duration(getenvInt("UEBA_LEARNING_DAYS", 7)) * 24 * time.Hour,
		Interval:       time.Duration(getenvInt("UEBA_INTERVAL_SECONDS", 30)) * time.Second,
	}
	go cluster.RunLeader(ctx, db, "ueba", uebaEngine.Run)

	janitorEngine := &janitor.Janitor{
		DB:        client,
		Retention: time.Duration(getenvInt("RETENTION_DAYS", 30)) * 24 * time.Hour,
		Interval:  time.Duration(getenvInt("RETENTION_INTERVAL_MINUTES", 60)) * time.Minute,
	}
	go cluster.RunLeader(ctx, db, "janitor", janitorEngine.Run)
	// 低危良性事件放久了自动按误报结案；0 关闭。Run 返回会被租约循环立刻重拉，关闭时干脆不启动
	if days := getenvInt("AUTO_CLOSE_BENIGN_DAYS", 7); days > 0 {
		autoClose := &janitor.AutoClose{DB: client, Days: days, Interval: time.Hour}
		go cluster.RunLeader(ctx, db, "auto-close-benign", autoClose.Run)
	}

	var credentialVault *hostimport.Vault
	if key := os.Getenv("HOST_CREDENTIAL_KEY"); key != "" {
		credentialVault, err = hostimport.NewVault(key)
		if err != nil {
			slog.Error("凭据加密配置无效")
			os.Exit(1)
		}
	}

	// AI 与外部情报查询配置：控制台保存的为准，环境变量是首次部署的默认值；密钥用上面同一把钥匙加密落库
	aiConf := &aiconf.Store{DB: client, Vault: credentialVault, Default: aiconf.Config{
		BaseURL: getenv("AI_BASE_URL", "http://localhost:11434/v1"), APIKey: os.Getenv("AI_API_KEY"),
		Model: os.Getenv("AI_MODEL"), PiModel: os.Getenv("PI_MODEL"),
		PTR: getenv("IPINFO_PTR", "true") == "true", VTKey: os.Getenv("VT_API_KEY"), VTAlertMin: getenvInt("VT_ALERT_MIN_ENGINES", 3),
	}}
	conf := func() aiconf.Config { return aiConf.Get(ctx) }
	// 研判与资产标注共用一个端点与模型，每次调用按当时的配置，用量按用途分开记
	llmFor := func(feature string) *triage.LLM {
		l := triage.NewLLM("", "", "", time.Duration(getenvInt("AI_TIMEOUT_SECONDS", 120))*time.Second)
		l.Endpoint = func() (string, string, string) { c := conf(); return c.BaseURL, c.Model, c.APIKey }
		l.OnUsage = aiconf.Recorder(client, feature)
		return l
	}

	// 资产图谱与攻击面：物化清单与依赖边始终运行；配置了研判与标注模型才做 AI 标注
	assetEngine := &assetmap.Engine{
		DB: client, SQL: db,
		LLM:      llmFor("annotate"),
		Interval: time.Minute,
		Refresh:  time.Duration(getenvInt("ASSET_ANNOTATE_REFRESH_HOURS", 24)) * time.Hour,
	}
	// 标注是后台批量调用：关掉 GLM 隐式思考、限住输出，耗时才稳定（实测 pve1 默认模式波动到 120 秒超时）
	assetEngine.LLM.NoThinking, assetEngine.LLM.MaxTokens = true, 2048
	go cluster.RunLeader(ctx, db, "assetmap", assetEngine.Run)
	// 公网目的地址的背景信息：反向解析默认开；配了 VirusTotal key 才查（会把外联的公网地址发给它）。开关与 key 每轮取
	ipEnricher := &assetmap.Enricher{
		DB: client, Settings: func() (bool, string, int) { c := conf(); return c.PTR, c.VTKey, c.VTAlertMin },
		VTPerMin: getenvInt("VT_PER_MINUTE", 4), VTPerDay: getenvInt("VT_PER_DAY", 500),
		TTL: time.Duration(getenvInt("IPINFO_TTL_DAYS", 7)) * 24 * time.Hour, Interval: time.Minute,
		HTTP: &http.Client{Timeout: 15 * time.Second},
	}
	go cluster.RunLeader(ctx, db, "ipinfo", ipEnricher.Run)

	hub := response.NewHub(client, os.Getenv("RESPONSE_ENABLED") == "true")
	allowlist := isolationAllowlist()

	// 研判引擎：AI 带只读调查工具逐个研判 incident
	triageEngine := &triage.Engine{
		DB:       client,
		Rules:    rules,
		LLM:      llmFor("triage"),
		Interval: time.Duration(getenvInt("AI_INTERVAL_SECONDS", 30)) * time.Second,
	}
	// 自动响应：显式开启才挂钩子，隔离真执行（仍受 RESPONSE_ENABLED 约束），白名单主机绝不自动隔离
	if os.Getenv("AUTO_RESPONSE_ENABLED") == "true" {
		triageEngine.OnVerdict = (&response.Auto{
			Hub:            hub,
			MinConfidence:  getenvInt("AUTO_RESPONSE_MIN_CONFIDENCE", 90),
			Exempt:         hostSet(os.Getenv("AUTO_RESPONSE_EXEMPT")),
			AllowEndpoints: allowlist,
		}).React
	}
	// 常驻：模型在控制台配上就开始研判，撤掉就停
	go cluster.RunLeader(ctx, db, "triage", triageEngine.Run)

	// 推送目标以控制台保存的为准，环境变量只是首次部署的默认值
	notifySettings := &notify.Settings{DB: client, Default: notify.Target{
		URL:         os.Getenv("WEBHOOK_URL"),
		Format:      getenv("WEBHOOK_FORMAT", "generic"),
		LinkBase:    os.Getenv("WEBHOOK_LINK_BASE"),
		MinSeverity: int16(getenvInt("WEBHOOK_MIN_SEVERITY", 0)),
	}}
	webhook := &notify.Webhook{Settings: notifySettings}
	notifier := &notify.Notifier{
		DB:         client,
		Settings:   notifySettings,
		Interval:   time.Duration(getenvInt("WEBHOOK_INTERVAL_SECONDS", 30)) * time.Second,
		WaitTriage: triageEngine.LLM.Enabled,
	}
	go cluster.RunLeader(ctx, db, "notify", notifier.Run)
	silentAfter := time.Duration(getenvInt("AGENT_SILENT_MINUTES", 10)) * time.Minute
	watcher := &liveness.Watcher{
		DB: client, Notify: webhook.Send,
		SilentAfter: silentAfter,
		Interval:    time.Minute,
	}
	go cluster.RunLeader(ctx, db, "liveness", watcher.Run)

	dedupWindow := time.Duration(getenvInt("ALERT_DEDUP_WINDOW_MINUTES", 5)) * time.Minute
	registry := prometheus.NewRegistry()
	registry.MustRegister(prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	metrics := telemetry.New(registry)
	processor := &ingest.Processor{
		DB: db, Rules: rules, Suppress: suppressions, Intel: intelStore,
		DedupWindow: dedupWindow, Metrics: metrics,
	}
	var events eventbus.Bus = eventbus.NewDirect(processor, metrics)
	hostname, _ := os.Hostname()
	instance := eventbus.InstanceName(hostname, os.Getpid())
	if natsURL := os.Getenv("NATS_URL"); natsURL != "" {
		queued, err := eventbus.NewJetStream(natsURL,
			instance, getenvInt("QUEUE_SHARDS", 32), getenvInt("QUEUE_REPLICAS", 1),
			int64(getenvInt("QUEUE_MAX_BYTES_GB", 20))*1024*1024*1024,
			time.Duration(getenvInt("QUEUE_MAX_AGE_HOURS", 168))*time.Hour, processor, metrics)
		if err != nil {
			slog.Error("JetStream 初始化失败", "err", err)
			os.Exit(1)
		}
		events = queued
		router, routeErr := response.NewNATSRouter(natsURL, instance)
		if routeErr != nil {
			slog.Error("跨节点指令路由初始化失败", "err", routeErr)
			os.Exit(1)
		}
		hub.Router = router
		defer router.Close()
		slog.Info("事件队列已启用", "url", natsURL, "shards", getenvInt("QUEUE_SHARDS", 32))
	} else {
		slog.Warn("NATS_URL 未配置，事件使用单机直连模式")
	}
	defer events.Close()

	go (&syslog.Server{
		DB:          client,
		Rules:       rules,
		Addr:        os.Getenv("SYSLOG_ADDR"),
		DedupWindow: dedupWindow,
		Suppress:    suppressions,
		Intel:       intelStore,
		Events:      events,
	}).Run(ctx)

	grpcAddr := getenv("GRPC_ADDR", ":8081")
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		slog.Error("gRPC 监听失败", "err", err)
		os.Exit(1)
	}
	tlsOpts, mtls, err := grpcsvc.ServerOptions()
	if err != nil {
		slog.Error("TLS 配置无效", "err", err)
		os.Exit(1)
	}
	if !mtls {
		slog.Warn("gRPC 未启用 mTLS，采集端通信为明文，仅适合本机调试")
	}
	grpcServer := grpc.NewServer(tlsOpts...)
	// agent 安装包：一键接入从这里下载，在线 agent 也按这里的版本自动升级（AGENT_AUTO_UPGRADE=false 关闭）
	dist := &enroll.Dist{Dir: os.Getenv("AGENT_DIST_DIR")}
	pb.RegisterAgentServiceServer(grpcServer, &grpcsvc.Server{
		DB:          client,
		Rules:       rules,
		DedupWindow: dedupWindow,
		Hub:         hub,
		Suppress:    suppressions,
		Intel:       intelStore,
		Events:      events,
		Dist:        dist,
		AutoUpgrade: os.Getenv("AGENT_AUTO_UPGRADE") != "false",
	})
	pb.RegisterSensorServiceServer(grpcServer, &grpcsvc.SensorServer{
		DB:          client,
		Rules:       rules,
		DedupWindow: dedupWindow,
		Suppress:    suppressions,
		Intel:       intelStore,
		Events:      events,
	})
	go func() {
		slog.Info("gRPC 启动", "addr", grpcAddr)
		if err := grpcServer.Serve(lis); err != nil {
			slog.Error("gRPC 退出", "err", err)
			os.Exit(1)
		}
	}()

	if err := cluster.WithLock(ctx, db, "bootstrap", func() error { return auth.Bootstrap(ctx, client) }); err != nil {
		slog.Error("初始化 admin 账号失败", "err", err)
		os.Exit(1)
	}

	httpAddr := getenv("HTTP_ADDR", ":8080")
	slog.Info("HTTP 启动", "addr", httpAddr)
	queryURLs := map[uuid.UUID]string{}
	if raw := os.Getenv("PI_QUERY_DATABASE_URLS"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &queryURLs); err != nil {
			slog.Error("PI_QUERY_DATABASE_URLS 必须是组 UUID 到只读 DSN 的 JSON 对象")
			os.Exit(1)
		}
	}
	// 组查询身份：手工配置的优先，其余由平台账号自动开通（需 CREATEROLE）
	queryRoles := &queryrole.Provisioner{DB: db, Client: client, BaseDSN: dsn, Static: queryURLs}
	go func() {
		queryRoles.Reconcile(ctx)
		if err := queryrole.DropDryRun(ctx, db); err != nil {
			slog.Error("删除遗留 dry_run 列失败，多半是仍有视图引用 commands.dry_run：手工开通的组视图需按新版 deploy/pi-query/group-views.sql 重建，其他手工视图需去掉该列，然后重启 server；在此之前该列只是不再被读取", "err", err)
		}
	}()
	piRuntime := piruntime.Runtime{Runner: getenv("PI_RUNNER_PATH", "/app/pi-runtime/runner.mjs"), Timeout: time.Duration(getenvInt("PI_TIMEOUT_SECONDS", 1800)) * time.Second}
	// 配了沙箱就让 Pi 在远端隔离容器里用默认工具干活；没配退回本机 runner 与平台自定义工具
	if url := os.Getenv("SANDBOX_URL"); url != "" {
		remote, err := piruntime.NewRemote(url, os.Getenv("SANDBOX_KEY"), os.Getenv("SANDBOX_CA_FILE"))
		if err != nil {
			slog.Error("沙箱配置无效", "err", err)
			os.Exit(1)
		}
		if strings.HasPrefix(url, "http://") {
			slog.Warn("平台与沙箱之间为明文，仅适合受信网络调试")
		}
		piRuntime.Remote = remote
		slog.Info("Pi 在沙箱中运行", "url", url)
	}
	chat := &agentchat.Service{Base: ctx, Rules: rules, Timeout: time.Duration(getenvInt("PI_TIMEOUT_SECONDS", 1800)) * time.Second, DB: client, Gate: &commandgate.Gate{DB: client, Hub: hub, ApprovalTimeout: time.Duration(getenvInt("PI_APPROVAL_TIMEOUT_SECONDS", 600)) * time.Second, Notify: webhook.Send},
		Runtime: piRuntime, Sandboxed: piRuntime.Sandboxed(),
		AI: func() (string, string, string) { c := conf(); return c.BaseURL, c.APIKey, c.PiModel }, Query: queryRoles}
	go chat.Recover(ctx)
	// 预设任务：Pi 启用才调度，集群单活；报告与失败通知走与 incident 相同的 webhook
	report.Chromium = getenv("CHROMIUM_PATH", "chromium")
	scheduler := &schedule.Scheduler{
		DB: client, Runner: chat,
		Dir:          getenv("TASKS_PATH", "../tasks"),
		Interval:     time.Duration(getenvInt("SCHEDULE_INTERVAL_SECONDS", 30)) * time.Second,
		DefaultModel: func() string { return conf().PiModel },
		Notify:       webhook.Send,
		Timeout:      time.Duration(getenvInt("PI_TIMEOUT_SECONDS", 1800)) * time.Second,
	}
	// 常驻：任务定义照常同步到库里，Pi 模型配上才运行
	go cluster.RunLeader(ctx, db, "schedule", scheduler.Run)
	enrollSvc, err := enroll.FromEnv(client, silentAfter)
	if err != nil {
		slog.Error("主机接入配置无效", "err", err)
		os.Exit(1)
	}
	if reason := enrollSvc.Disabled(); reason != "" {
		slog.Warn("主机在线接入未启用", "reason", reason)
	}
	routes := http.NewServeMux()
	routes.Handle("/api/host-import/", api.HostImports(&hostimport.Service{DB: client, Vault: credentialVault}, enrollSvc, os.Getenv("ENROLL_PUBLIC_URL"), getenv("ENROLL_SSH_ENABLED", "false") == "true"))
	routes.Handle("/api/settings/", api.Settings(client, notifySettings, webhook, aiConf, db))
	routes.Handle("/api/intel/feeds", api.IntelFeeds(client, intelFeeds))
	routes.Handle("/api/intel/feeds/", api.IntelFeeds(client, intelFeeds))
	enrollTokens := api.EnrollTokens(client, enrollSvc, dist)
	routes.Handle("/api/enroll-tokens", enrollTokens)
	routes.Handle("/api/enroll-tokens/", enrollTokens)
	// 日志检索里的「问 AI」：交互式调用，同样关掉隐式思考、限住输出，等得起
	explainLLM := llmFor("explain")
	explainLLM.NoThinking, explainLLM.MaxTokens = true, 1500
	eventAI := api.EventAI(client, explainLLM)
	for _, path := range api.EventAIPaths {
		routes.Handle(path, eventAI)
	}
	assetMap := api.AssetMap(client, assetEngine.LLM.Enabled)
	for _, path := range api.AssetMapPaths {
		routes.Handle(path, assetMap)
	}
	routes.Handle("/", api.Handler(client, rules, hub, suppressions, intelStore, allowlist, chat))
	app := auth.Middleware(client, routes)
	mux := http.NewServeMux()
	mux.Handle("/metrics", telemetry.Handler(registry))
	// 接入端点免登录：安装脚本与二进制公开，注册靠令牌
	mux.Handle("/api/enroll/", enrollSvc.Public(dist))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := db.PingContext(r.Context()); err != nil || !events.Ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})
	mux.Handle("/", app)
	// 经反向代理时还原客户端地址，登录退避与审计才按真人计
	trustedProxies, err := realip.Parse(os.Getenv("TRUSTED_PROXIES"))
	if err != nil {
		slog.Error("TRUSTED_PROXIES 配置无效", "err", err)
		os.Exit(1)
	}
	httpServer := &http.Server{Addr: httpAddr, Handler: realip.Middleware(trustedProxies, mux), ReadHeaderTimeout: 10 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	httpErr := make(chan error, 1)
	go func() { httpErr <- httpServer.ListenAndServe() }()
	select {
	case err := <-httpErr:
		if !errors.Is(err, http.ErrServerClosed) {
			slog.Error("HTTP 退出", "err", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		slog.Info("收到退出信号，开始排空连接")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
	chat.Wait(shutdownCtx)
	grpcDone := make(chan struct{})
	go func() { grpcServer.GracefulStop(); close(grpcDone) }()
	select {
	case <-grpcDone:
	case <-shutdownCtx.Done():
		grpcServer.Stop()
	}
}

func configureLogging() {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	if os.Getenv("LOG_FORMAT") == "json" {
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, opts)))
		return
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, opts)))
}

// ensureSearchIndex 事件全文检索的 trgm 索引。没有它，关键词检索在大表上
// 是全表扫。CREATE EXTENSION 需要数据库权限，失败只降级警告——检索仍然可用，
// 只是慢，比起启动失败这是正确的取舍。
func ensureSearchIndex(ctx context.Context, db *sql.DB) {
	stmts := []string{
		"CREATE EXTENSION IF NOT EXISTS pg_trgm",
		"CREATE INDEX IF NOT EXISTS events_raw_trgm ON events USING gin ((raw::text) gin_trgm_ops)",
	}
	for _, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			slog.Warn("检索索引未启用，大数据量下关键词搜索会退化为全表扫描", "err", err)
			return
		}
	}
}

// isolationAllowlist 隔离主机时必须放行的地址。默认放行 server 的 gRPC 端点，
// 否则 agent 隔离后收不到解除指令，只能人工上机处理。
func isolationAllowlist() []string {
	if v := os.Getenv("ISOLATION_ALLOW"); v != "" {
		return strings.Split(v, ",")
	}
	slog.Warn("未配置 ISOLATION_ALLOW，主机隔离将被 agent 拒绝执行")
	return nil
}

// hostSet 逗号分隔的主机名清单转集合。
func hostSet(v string) map[string]bool {
	set := map[string]bool{}
	for _, h := range strings.Split(v, ",") {
		if h = strings.TrimSpace(h); h != "" {
			set[h] = true
		}
	}
	return set
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return def
}
