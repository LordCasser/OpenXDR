# 部署与使用手册

从单机试用到接入主机、开启检测与处置的完整操作说明。设计原理见 [architecture.md](architecture.md)，
跨宿主机高可用部署见 [deploy/ha](../deploy/ha/README.md)，AI 助手与巡检任务见 [pi-backend.md](pi-backend.md)。

## 启动与初始配置

```bash
# 启动 JetStream + Postgres + server + web
docker compose up -d
# 界面: http://localhost:5173   API: http://localhost:8080   gRPC 接入: 8081
```

数据库表由 server 启动时自动创建，无需手动迁移。

首次启动会创建 `admin` 账号：密码取 `ADMIN_PASSWORD` 环境变量，
未配置则随机生成并打印在 server 日志里（`docker compose logs server | grep admin`）。
登录后可在界面里建号，角色三档：admin（用户管理）/ analyst（研判与处置）/ viewer（只读）。
所有登录与处置操作都有审计日志，admin 可在界面查看。

启用告警通知：admin 在控制台「系统设置 → 通知」填入 IM 机器人地址，点「发送测试」确认收到后保存。
研判后的事件、主机失联与恢复、巡检报告都推到这里。benign 判定不推（AI 说是噪声的不打扰人），
但高危及以上照推并标注「需人工复核」。格式支持 generic / dingtalk / feishu / wecom。
也可以用环境变量给出首次部署的默认值，控制台保存过之后以控制台为准：

```bash
WEBHOOK_URL=https://oapi.dingtalk.com/robot/send?access_token=... \
WEBHOOK_FORMAT=dingtalk \
WEBHOOK_LINK_BASE=http://<控制台地址>:5173 \
docker compose up -d
```

启用 AI 研判（不配置则只做规则告警和关联，不调用模型）：

```bash
AI_MODEL=qwen3 docker compose up -d   # 默认接本机 Ollama
```

研判是**主动调查**式的：模型可以调用工具检索原始事件、追进程血缘、
查主机告警前科，像分析师一样查证后再定性（最多 6 轮）。模型不支持
tool calling 时自动退化为单轮研判，无需配置。

刻意不做自然语言到 SQL 的翻译——工具的参数空间受限且已转义，模型再怎么发挥
也越不出这个边界。想用自然语言追问数据（「最近有没有主机连过这个 IP」）时用
「AI 助手」：它按组的只读视图查库、在主机上执行命令，高风险命令要组管理员批准。

也可以接任意 OpenAI 兼容端点，包括自建的私有化部署：

```bash
AI_BASE_URL=http://<推理服务>/v1 \
AI_MODEL=<模型名> \
AI_API_KEY=<密钥> \
AI_TIMEOUT_SECONDS=300 \
docker compose up -d
```

推理服务在内网时注意 `NO_PROXY`：Go 默认读取 `HTTP_PROXY` 环境变量，
若部署环境设了代理，内网端点的请求会被错误地转发出去。

实测接入自建 DeepSeek-V4-Flash（6× RTX 5090，vLLM）：单个 incident 研判
5–13 秒，模型能从事件图里读出父进程并给出可执行的处置建议。推理型模型返回的
`reasoning_content` 不影响解析，引擎只取 `content` 里的 JSON。

### 添加主机

已有运维文档时，可从资产页「从文档导入」识别主机地址、账号密码或私钥，预览确认后
按组保存资产和加密凭据，再单独发起 SSH 纳管。格式、权限和配置见
[文档导入与主机纳管](host-enrollment.md)。

在控制台「资产 → 添加主机」选好组，复制安装命令到被监控主机上执行：

```bash
# Linux（root）
curl -fsSL https://<控制台>/api/enroll/install.sh | sudo sh -s -- https://<控制台> <接入令牌>
# Windows（管理员 PowerShell）
& ([scriptblock]::Create((irm https://<控制台>/api/enroll/install.ps1))) https://<控制台> <接入令牌>
```

控制台必须是主机信任其证书的 HTTPS 地址：脚本、agent 与令牌都经它传输，明文会被中间人
篡改成任意代码以 root 执行。非 HTTPS 访问时控制台不给出安装命令，脚本也会拒绝运行。
失败时脚本原样打印 server 给出的原因（令牌无效、主机名已有在线 agent 等）；
新私钥在签发成功前只暂存，失败的重装不会破坏已安装主机的身份。

脚本会下载 agent、在本机生成私钥并由 server 签发主机绑定证书、写好配置、注册为
systemd 服务（Windows 为 SYSTEM 身份的开机计划任务）。主机自动进入令牌所属的组，
当晚就会出现在每日巡检报告里。令牌按组签发、默认 7 天有效
（最长 30 天）、有效期内可批量装机、随时可撤销。已有在线 agent 的主机名不能被
重复接入，令牌也不能把别组的主机改到本组。

之后不用再登录主机升级：把新版安装包放进 server 的 `AGENT_DIST_DIR`，在线 agent 下次重连
（server 滚动发布时就会重连）会经已认证的 gRPC 通道下载、校验哈希、自检能运行后替换自己并重启，
旧版保留为 `openxdr-agent.prev`。分发目录里放的是哪个版本，整片主机就收敛到哪个版本；
`AGENT_AUTO_UPGRADE=false` 关闭。资产详情里能看到每台主机的 agent 版本。

server 侧需要三样东西才会开放在线接入（缺哪样控制台会直接说明）：

- `ENROLL_GRPC_URL`：主机上能访问到的 gRPC 地址，如 `https://xdr.internal:8081`
- 开了 mTLS 时：`TLS_CA_KEY_FILE` 指向 CA 私钥（gencerts 生成的 `ca.key`），用于签发主机证书。
  `TLS_CA_FILE` 可以是多张 CA 的信任包，签发用其中与私钥配对的那张、下发给 agent 的是整个信任包——
  原 CA 私钥丢失时另起一张接入 CA 追加进信任包即可，已有证书不受影响
- `AGENT_DIST_DIR`（compose 已挂 `./dist`）里放 agent 安装包：
  `openxdr-agent-linux-amd64`、`openxdr-agent-linux-arm64`、`openxdr-agent-windows-amd64.exe`

也可以手工构建部署：

```bash
# 端点 agent（Linux 需 root 才能用 eBPF，否则自动回落轮询采集）
cd agent && cargo build --release
sudo OPENXDR_SERVER=http://<server>:8081 ./target/release/openxdr-agent

# 流量探针（需 root，网卡接核心交换机镜像口）
cd sensor && cargo build --release
sudo env SENSOR_IFACE=eth0 OPENXDR_SERVER=http://<server>:8081 ./target/release/openxdr-sensor
```

探针有两个抓包后端，用 `SENSOR_BACKEND` 切换：

| 后端 | 说明 |
|---|---|
| `afpacket`（默认） | AF_PACKET v3 零拷贝环 + FANOUT 按流哈希。任何 Linux 都能跑，不挑驱动，收发双向都能看到 |
| `afxdp` | 绕过协议栈，吞吐更高。需 `--features xdp` 构建、驱动支持，进程会在网卡上挂载 XDP 程序；**只能看到入向流量**，镜像口场景够用 |

`SENSOR_WORKERS` 决定并行度。afpacket 下多个 worker 共享 FANOUT 组；afxdp 下
worker 号即网卡队列号，数量不应超过网卡实际队列数。

### 按主机下发采集配置

采集范围不必编译期写死，可按主机调整：

```bash
curl -X PUT http://localhost:8080/api/assets/<asset-id>/config \
  -H 'Content-Type: application/json' -b cookie.txt \
  -d '{"fileWatchDirs": ["/srv/app", "/opt/secrets"], "collectAuth": false}'
```

配置随 agent 下次注册生效——agent 断线重连本就会重新注册，因此没有
单独的热更新通道。坏配置一律退回内置默认：让 agent 变瞎比配置不生效严重得多。

### 采集方式

内核态（零环）始终是可选项，用户态（三环）也能完整工作：

| 层次 | 方式 | 覆盖 | 前提 |
|---|---|---|---|
| 零环（可选） | Linux eBPF tracepoint | 全部 exec/exit，内核直接给出路径；TCP 出站连接 | `--features ebpf` + root |
| 三环（默认） | Linux netlink proc connector | 全部 exec/exit 通知，信息从 /proc 现补 | CAP_NET_ADMIN + 初始 pid 命名空间 |
| 三环 | Windows ETW | 进程启动与退出事件 | 管理员 |
| 三环（兜底） | 进程表轮询 | 每秒快照，漏短命进程 | 无 |
| 三环（并行） | Linux fanotify / inotify | 敏感文件变更（cron、sudoers、SSH 密钥、systemd 单元等），fanotify 路径带进程上下文 | 无（fanotify 需 CAP_SYS_ADMIN，不足自动退 inotify） |
| 三环（并行） | Windows ReadDirectoryChangesW | 敏感目录文件变更（drivers/etc、config 等） | 无 |
| 三环（并行） | Windows 快照 diff | 注册表自启动键（Run/RunOnce/Winlogon）、Startup 目录、服务与计划任务 | 无 |
| 三环（并行） | Linux wtmp/btmp | 登录成功与失败事件，认证可见性不依赖 syslog | 可读 /var/log/btmp |
| 三环（并行） | Windows Security 日志 | 4624/4625 登录成功与失败（含状态码） | 管理员或 Event Log Readers |

netlink 在**容器或 WSL2 里不可用**：proc connector 报的是初始 pid 命名空间的
pid，在嵌套命名空间中对不上本地 /proc，采出来全是错 pid、空进程名的垃圾。
agent 启动时会检测命名空间并主动退回轮询——宁可弱一点，也不产出假数据。

采集端默认构建**不依赖任何外部二进制**——protoc 随 crate 分发，`cargo build` 直接可用。
内核级采集是可选特性，开启后才需要 nightly 工具链：

```bash
rustup toolchain install nightly --component rust-src
cargo +nightly install bpf-linker

cargo build --release --features ebpf   # agent：Linux eBPF 采集
cargo build --release --features xdp    # sensor：AF_XDP 后端
```

不开这两个特性时，agent 走 netlink proc connector（失败再退轮询）、sensor 走 AF_PACKET，功能完整只是精度和吞吐低一些。

## 日志接入

server 内置 syslog 接收（同端口 UDP + TCP，RFC3164 与 RFC5424 都支持），
配置 `SYSLOG_ADDR` 启用：

```bash
SYSLOG_ADDR=:514 docker compose up -d

# 被监控主机把日志转发过来
echo '*.* @<server>:514' >> /etc/rsyslog.conf && systemctl restart rsyslog
```

日志按主机名归属资产，主机名对不上时退回源 IP 匹配，两者都对不上则归入
统一的未归属 incident。同一主机反复报同一条日志只留一行告警并计数。

规则里用 `logsource.category: application` 匹配这类事件，字段路径见
`rules/lnx_ssh_auth_failure.yml`。

## 威胁情报

内置 IOC 库：恶意 IP / 域名 / 文件哈希。三路事件（EDR / NTA / 日志）入库时
自动与情报碰撞，命中即产生告警，走与规则告警相同的去重、抑制与关联链路。
域名情报按后缀匹配，`evil.com` 能撞上 `c2.evil.com` 的 DNS 查询、TLS SNI 与 HTTP Host。
哈希情报撞的是 agent 随进程事件上报的 exe SHA-256（同一二进制只算一次，缓存按 mtime 失效）。

**情报订阅**开箱即用：内置 abuse.ch Feodo Tracker（僵尸网络 C2 IP）、ThreatFox
（近期恶意软件 IP / 域名 / 哈希）、URLhaus（恶意软件分发域名）与 Emerging Threats
（失陷主机 IP）四个公开源，默认全部开启，server 单活每 `INTEL_FEED_INTERVAL_HOURS`
（默认 6）小时拉取一次。内网与保留地址不入库；ThreatFox 的 URL 只收主机是 IP 的，
挂在 GitHub 之类公共平台上的恶意 URL 若按主机名入库会误伤正常访问。手工录入的同值情报
优先；源里撤下的条目约两天后到期失效，关掉的源立即清空。在「威胁情报」页可逐个开关、
立即同步，并直接看到哪些订阅情报命中过。server 需要能访问这些源（可经 `HTTPS_PROXY`）。

界面上（威胁情报入口）还可直接粘贴清单批量导入：一行一条，类型自动识别，
重复条目跳过。每条情报持续累计命中次数——长期零命中的陈年 IOC 应当清理，
默认可设有效期到期自动失效。也可通过 API 对接情报源：

```bash
curl -X POST http://localhost:8080/api/intel/import \
  -H 'Content-Type: application/json' -b cookie.txt \
  -d '{"text": "6.6.6.6\nevil.example.com", "source": "feed-x", "expiresInDays": 30}'
```

## 误报抑制

分析师把事件标记为误报后，可以顺手把噪声源掐掉：抑制指定规则在指定主机
（或全部主机）上的告警。抑制后事件照常入库，只是不再产生告警——证据不丢，
只是不再打扰人。

抑制从不静默：每条抑制规则持续累计被压掉的次数，可在抑制清单里看到并随时撤销。
默认带有效期，避免抑制规则无限积累后悄悄吃掉真实告警。

## 响应处置

检测到攻击后可以直接下发处置指令：**结束进程**、**隔离主机**、**解除隔离**。
指令走 agent 主动连出的双向通道，被监控主机不需要开监听端口。

这是系统里唯一能对主机造成实际影响的功能。指令一律真执行，没有演练模式，闸门默认全开：

| 闸门 | 行为 |
|---|---|
| 全局开关 | `RESPONSE_ENABLED` 默认 false，不开则一律拒绝下发 |
| 隔离自保 | 未配置 `ISOLATION_ALLOW` 时 agent 拒绝隔离——隔离后收不到解除指令只能人工上机 |

```bash
RESPONSE_ENABLED=true ISOLATION_ALLOW=<server>:8081 docker compose up -d
```

每条指令连同下发者、执行结果一并落库，可在事件详情页查看。
隔离在 Linux 用 nftables 独立表实现（不触碰主机原有规则），Windows 使用独立 WFP 子层：管理端点许可优先于本子层的默认阻断，规则以事务原子更新并持久化。
Windows 放行地址必须为数字 IP 或 IP:端口（IPv6 为 `[地址]:端口`），最多 128 项；
解除隔离同时清理旧版 `OpenXDR-Isolation-*` 规则。部署前需在有本地控制台的 Windows 测试机
验证隔离、管理通道重连、解除隔离及 Agent 重启后的行为。

结束进程必须携带采集事件中的 `processGuid` 和 `pid`，Agent 同时校验 GUID 与创建时间，
通过 Linux pidfd（需内核支持）或 Windows 进程句柄执行，身份不明时拒绝，绝不退回裸 PID。
指令通道独立断开时会每 5 秒重连；所有动作均不自动重放，避免过期的隔离/解除意图再次生效。
跨节点确认丢失记录为 unknown；重新操作前需检查原指令记录与主机实际状态。

## ATT&CK 覆盖

规则的 Sigma `tags` 会被解析成 ATT&CK 战术与技术，界面「检测规则 → ATT&CK 覆盖」标签按
杀伤链顺序出矩阵。空列就是检测缺口，不是排版问题。

矩阵还会标出**有规则但无数据源**的格子——纸面覆盖率与真实覆盖率的差额，
这是挂载大规则库后最容易自欺欺人的地方。

覆盖率不靠自我感觉：`validation/` 下是攻击手法的真实命令行语料，
`go run ./cmd/detectcheck` 回放过引擎，验证规则真能抓住 Atomic Red Team
实际执行的命令，且命中的规则标了对应技术。CI 每次都跑，规则改动
导致检测退化会直接失败。

## 导入社区规则

规则引擎兼容 Sigma，可直接挂载 [SigmaHQ](https://github.com/SigmaHQ/sigma) 规则库：

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma.git
RULES_PATH=sigma/rules docker compose up -d

# 导入前先看兼容情况
cd server && go run ./cmd/sigmacheck ../sigma/rules
```

对 SigmaHQ 3141 条规则的实测：**加载 2149 条（68.4%）**，其中 1393 条有现成数据源可命中，
其余等待对应遥测接入（文件、模块加载、HTTP）。未加载的主要是我们不采集的数据源
（注册表、PowerShell 脚本块、云平台审计日志）。

引擎对拿不准的规则一律拒绝加载而不是降级处理——用了未实现修饰符（如 `|cidr`）的规则
如果被当成普通字符串匹配，`condition: not selection` 这类规则会对每个事件误报。
同理，Windows 规则不会在 Linux 资产的事件上求值。

## 启用 mTLS

采集端与 server 之间默认是明文，仅适合本机调试。生产部署必须开双向认证：

```bash
cd server && go run ./cmd/gencerts ../certs <server 的域名或 IP>

# server
TLS_CA_FILE=certs/ca.crt TLS_CERT_FILE=certs/server.crt TLS_KEY_FILE=certs/server.key ...

# agent / sensor（注意地址是 https）
OPENXDR_SERVER=https://<server>:8081 \
OPENXDR_CA=certs/ca.crt OPENXDR_CERT=certs/client.crt OPENXDR_KEY=certs/client.key ...
```

三个变量必须同时配置，只配一部分会直接报错而不是悄悄降级成明文。
目录里已有 `ca.crt`/`ca.key` 时 gencerts 沿用这个 CA 只签新证书，不会让已发出的证书失效。

通用 client 证书所有采集端共用，持证者可以冒充任何主机上报。给 agent 逐台发
绑定证书可以消除这一点（sensor 没有主机身份，继续用通用证书）：

```bash
# 在通用证书之外，为 web01、db01 各签一张身份绑定的证书
go run ./cmd/gencerts ../certs <server 地址> web01 db01

# web01 上的 agent 用自己的证书，server 会强制它只能以 web01 的身份注册、上报、接收指令
OPENXDR_CERT=certs/agent-web01.crt OPENXDR_KEY=certs/agent-web01.key ...
```

绑定是证书自身的属性（CN 前缀 `host:`），失陷主机拿自己的证书冒充不了别人。

## 配置

server 全部通过环境变量配置，均有默认值：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `DATABASE_URL` | `postgres://openxdr:openxdr@localhost:5432/openxdr?sslmode=disable` | 数据库连接串 |
| `NATS_URL` | 空（单机直连） | NATS 地址；配置后启用 JetStream 持久队列，多个地址用逗号分隔 |
| `QUEUE_SHARDS` | `32` | 事件一致性分片数；同一资产保持有序 |
| `QUEUE_REPLICAS` | `1` | JetStream stream 副本数；三节点生产集群设为 3 |
| `QUEUE_MAX_BYTES_GB` | `20` | 事件 stream 最大磁盘占用 |
| `QUEUE_MAX_AGE_HOURS` | `0` | 必须为 0；未处理消息不自动过期，容量满则拒收新消息 |
| `LOG_FORMAT` | 空（text） | 设为 `json` 输出结构化日志 |
| `LOG_LEVEL` | `info` | debug / info / warn / error |
| `RULES_PATH` | `../rules` | Sigma 规则目录 |
| `IDENTITY_RUN_RETENTION_DAYS` | `30` | 目录终态运行记录保留天数，0 关闭历史删除，范围 0–3650；每来源最新记录保留，过期运行回收不受此开关影响 |
| `IDENTITY_SOURCES_JSON` | 空（关闭） | 多目录只读账号同步，严格 JSON 数组；凭据通过环境变量名引用，组须已存在，配置后重启生效。见 [身份来源配置](identity-correlation.md#启动配置与定时同步) |
| `TEMPORAL_RULES_PATH` | 空（关闭） | 时序规则独立目录；配置后与基础规则整批严格加载，共用 RULES_RELOAD_SECONDS 重载周期。容器使用容器内路径，需额外挂载；见 [时序检测](temporal-detection.md) |
| `RULES_RELOAD_SECONDS` | `30` | 规则目录变更检测周期，变更自动热重载；0 关闭 |
| `TASKS_PATH` | `../tasks` | 预设任务 YAML 目录；配置了 Pi 模型（`PI_MODEL` 或控制台）才运行，见 [Pi 后端](pi-backend.md#预设任务) |
| `SCHEDULE_INTERVAL_SECONDS` | `30` | 任务到期检查与 YAML 重载周期 |
| `CHROMIUM_PATH` | `chromium` | 报告 PDF 渲染用的 headless Chromium，server 镜像已内置 |
| `HTTP_ADDR` / `GRPC_ADDR` | `:8080` / `:8081` | 监听地址 |
| `ALERT_DEDUP_WINDOW_MINUTES` | `5` | 告警去重窗口 |
| `CORRELATE_WINDOW_MINUTES` | `30` | 关联时间窗 |
| `CORRELATE_MAX_GRAPH_NODES` | `500` | 单个事件图节点上限 |
| `AI_MODEL` | 空（不启用） | 事件研判与资产标注的模型名。**`AI_*`、`PI_MODEL`、`VT_API_KEY`、`IPINFO_PTR`、`VT_ALERT_MIN_ENGINES` 也能在控制台「系统设置 → AI 模型 / 外部情报」里改**，保存过的项以控制台为准、十几秒内全集群生效，环境变量只是首次部署的默认值；控制台保存的密钥用 `HOST_CREDENTIAL_KEY` 加密，没配这把钥匙时只能用环境变量提供密钥 |
| `AI_BASE_URL` | `http://localhost:11434/v1` | OpenAI 兼容端点 |
| `SYSLOG_ADDR` | 空（不启用） | syslog 监听地址，如 `:514`。UDP 与 TCP 同时监听 |
| `SUPPRESSION_RELOAD_SECONDS` | `30` | 抑制规则重载与命中计数回写周期 |
| `INTEL_RELOAD_SECONDS` | `30` | 威胁情报重载与命中计数回写周期 |
| `WEBHOOK_MIN_SEVERITY` | `0` | 低于该级别的事件不推送（1 信息 ~ 5 严重），0 表示全推。控制台保存过通知配置后以控制台为准 |
| `AGENT_SILENT_MINUTES` | `10` | agent 指令通道超过该时长没有心跳即判失联并通知，恢复时再通知一次 |
| `HOST_CREDENTIAL_KEY` | 空 | 文档导入凭据的 AES-256-GCM 密钥，base64 编码 32 字节；HA 节点必须一致 |
| `ENROLL_SSH_ENABLED` | `false` | 允许组管理员使用保存凭据进行 SSH 纳管 |
| `ENROLL_PUBLIC_URL` | 空 | 被纳管主机可访问的可信 HTTPS 控制台地址 |
| `ENROLL_GRPC_URL` | 空（不启用在线接入） | 写进 agent 配置的 gRPC 地址，主机上必须能访问 |
| `TLS_CA_KEY_FILE` | 空 | CA 私钥，开了 mTLS 时在线接入用它签发主机证书 |
| `AGENT_DIST_DIR` | 空 | agent 安装包目录，供安装脚本下载，也是在线 agent 自动升级的目标版本 |
| `AGENT_AUTO_UPGRADE` | `true` | 在线 agent 与安装包哈希不同时自动升级，`false` 关闭 |
| `TRUSTED_PROXIES` | 空 | 可信反向代理的地址或网段（逗号分隔）。只有来自这些地址的请求才采信 `X-Forwarded-For`，从右往左取第一个不可信地址作为客户端，登录退避与审计按它记来源；留空不还原 |
| `INTEL_FEED_INTERVAL_HOURS` | `6` | 情报订阅同步周期（小时），订阅条目有效期为它的 8 倍 |
| `RESPONSE_ENABLED` | `false` | 是否允许下发响应指令；开启后人工处置、Pi 命令、定时任务与自动响应下发的指令都会真执行 |
| `ISOLATION_ALLOW` | 空 | 隔离主机时放行的地址，必须包含 server 的 gRPC 端点 |
| `AUTO_RESPONSE_ENABLED` | `false` | AI 研判高置信度 malicious 时真实隔离涉事主机（依赖 `RESPONSE_ENABLED`，每次决策落审计） |
| `AUTO_RESPONSE_MIN_CONFIDENCE` | `90` | 触发自动响应的置信度门槛 |
| `AUTO_RESPONSE_EXEMPT` | 空 | 逗号分隔的主机名，绝不自动隔离 |
| `UEBA_LEARNING_DAYS` | `7` | 首次出现检测的按资产学习期 |
| `BEACON_ENABLED` | `1` | 外联心跳检测（新出现的规律公网外联），0 关闭 |
| `COLLECTOR_DROP_ALERT` | `1000` | 一分钟内丢弃这么多事件就推「采集异常」，0 不看丢事件；采集器降级或缓存写不进去照常推送 |
| `PI_HISTORY_FOLD_KB` | `64` | Pi 会话历史超过这么多 KB 时折叠较早的工具结果再发给模型，0 不折叠 |
| `VULN_SYNC_HOURS` | `24` | 漏洞库（OSV）同步周期，0 关闭 |
| `VULN_OSV_URL` | `https://osv-vulnerabilities.storage.googleapis.com` | OSV 下载地址，可指向内网镜像 |
| `VULN_DIR` | 空 | 离线漏洞库目录（放 `Debian.zip`、`Ubuntu.zip`），设置后不联网 |
| `BEACON_LEARNING_DAYS` | `7` | 外联心跳学习期，按资产接入时间算；首次启用回放这段历史只学不报 |
| `RETENTION_DAYS` | `30` | 原始事件保留天数，0 表示不清理。被告警引用的证据事件不受影响 |
| `IPINFO_PTR` | `true` | 对资产连过的公网地址做反向解析（PTR），结果缓存，供图谱展示与 AI 标注认地址；内网没有外部解析时可设 `false` |
| `VT_ALERT_MIN_ENGINES` | `3` | VirusTotal 判恶意的引擎数达到该值，就把地址加入威胁情报（来源 virustotal，随缓存期到期），之后再有主机连它即按情报命中告警；重查后不再达到即失效，人工录入的同一地址不动；0 关闭 |
| `VT_API_KEY` | 空 | VirusTotal API key。配置后查询公网目的地址的归属、国家、恶意判定与历史解析域名；**会把资产连过的公网 IP 发给 VirusTotal**，不配置则不查 |
| `VT_PER_MINUTE` / `VT_PER_DAY` | `4` / `500` | VirusTotal 查询限额（默认按免费额度），撞到 429 自动等下一分钟 |
| `IPINFO_TTL_DAYS` | `7` | 公网地址信息的缓存期（天），到期重查 |
| `ASSET_ANNOTATE_REFRESH_HOURS` | `24` | 资产 AI 标注的定时刷新周期（小时），0 表示只在事实变化或人工要求时标注；需配置 `AI_MODEL`，见 [资产图谱与攻击面](asset-map.md) |
| `AUTO_CLOSE_BENIGN_DAYS` | `7` | 未结案事件 AI 判良性、最高级别低于 4（高危）且创建超过 N 天时，每小时由系统按 `false_positive` 自动结案并记审计；0 表示关闭 |

AI 助手相关的 `PI_*` 变量见 [pi-backend.md](pi-backend.md#配置)；按包整理的完整清单见 [detection.md](detection.md#server-环境变量全清单servermaingo)。
