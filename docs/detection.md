# 检测与降噪链路

本文是 server 检测管线的完整参考，逐包对照代码核实并标注源码位置。
事件字段 schema 见 [events.md](events.md)，采集行为见
[collection.md](collection.md)。

## 处理链总览

三条接入路径先生成统一版本化信封；启用 JetStream 时持久入队，单机直连时直接
调用同一个 `ingest.Processor`：

```
稳定 event_id + partition_key（按资产分片）
  → JetStream durable consumer（处理成功才 ACK）
  → 事件主键幂等落库
  → ① sigma 规则求值 + 情报碰撞（合并成同一命中序列）
  → ② 抑制检查（被压掉的命中不占去重槽位）
  → ③ 去重（窗口内同指纹只留一行，count 累加）
  → ④ 告警落库
```

之后是集群单活的**异步**后台循环；PostgreSQL advisory lease 保证同名任务
只有一个节点执行，leader 失联后其他节点接管：

```
correlate：未归属告警 → incident（10s 一批）
triage：   open incident → LLM 研判 → verdict（30s 一批，需 AI_MODEL）
notify：   研判后事件 → webhook（30s 一批，benign 不推，高危 benign 照推待复核）
ueba：     扫进程事件维护基线，首次出现合成 low 告警进同一管线（30s 一批）
beacon：   增量读出站连接，新出现的规律公网外联合成 medium 告警（300s 一批）
janitor：  过期事件/会话清理（60min 一批，告警引用的证据不删）
```

另有两个**合成告警**源在 ingest 侧直接进管线（都走去重、可被抑制）：

- `xdr:bruteforce-success`（critical）：爆破得手升级，见下文
- `xdr:new-process`（low）：UEBA 首次出现，见下文
- `xdr:beacon`（medium）：新出现的外联心跳，见下文

sensor 与 syslog 路径结构相同，仅去重指纹与资产归属不同
（sensor 按源 IP 归属资产，`sensor.go:67-98`；syslog 按主机名→源 IP 两级，
`syslog/server.go:221-243`）。

## Sigma 规则引擎（`server/internal/sigma`）

**设计原则：拿不准就拒绝加载，绝不降级匹配。** 用了未实现修饰符的规则如果
被当成普通字符串匹配，`condition: not selection` 这类规则会对每个事件误报
（`engine.go:699-701`）。

### 能力边界

| 维度 | 支持 | 不支持（拒绝加载） |
|---|---|---|
| 修饰符 | `contains / startswith / endswith / re / all / cidr / windash`，正则标志 `i / m / s` | `base64`、`base64offset`、`fieldref` 等其余一切 |
| 条件 | `not/and/or`、括号、优先级 not>and>or；`1/all/any of them/pattern*`（`condition.go:9,176-217`） | 统计型条件 `count/min/max/avg/sum/near`（`engine.go:537-539`） |
| product | `windows / linux / macos`（`engine.go:153-155`） | 其余 product；既无 category 又无 product 的规则（`engine.go:595-606`） |
| category | 见下方映射表 | 未知 category（报"数据源未覆盖"，`engine.go:588-592`） |

修饰符语义：`re` 强制 `(?i)`（`m`、`s` 标志照常生效）；无通配符走 strings 精确/包含/前后缀（小写
比较）；有 `*?` 通配符 QuoteMeta 后转正则；值列表默认 OR，`|all` 转 AND；
值为 `null` 表示字段必须缺失；`cidr` 按网段匹配地址（含 v4 映射的 v6）；`windash` 把参数前缀的 `-`
展开成 `-`、`/` 与几种长破折号写法。

字段对齐：除了字段名映射（`fieldMap`），取值约定也要对上——`Initiated: true/false` 翻译成事件里的
`outbound/inbound`；`User` 取 `actor.user.name`，求值前由信封上的用户名补进去（入库的原始事件不改）；
父进程字段（`ParentImage`、`ParentCommandLine`）由 agent 在进程启动事件里直接带上。

### category → class_uid 映射（`engine.go:78-111`）

| Sigma category | class_uid | 现有采集来源 |
|---|---|---|
| process_creation / process_access / process_tampering / create_remote_thread | 1007 | ✅ agent |
| file_event / file_change / file_delete / file_access / file_rename / create_stream_hash | 1001 | ✅ agent（Linux fanotify/inotify + Windows RDCW/Startup/计划任务快照） |
| registry_set / registry_add / registry_event / registry_delete | 201002 | ✅ agent（Windows 快照 diff） |
| network_connection | 4001 | ✅ agent（eBPF）/ sensor |
| dns_query / dns | 4003 | ✅ sensor |
| authentication | 3002 | ✅ agent |
| application / antivirus | 100001 | ✅ syslog |
| image_load / driver_load | 1005 | ✅ Linux 内核模块快照 diff |
| proxy / webserver | 4002 | ❌ 无采集来源 |

`fieldMap`（`engine.go:31-74`）把 Sigma 标准字段名映射到 OCSF dot path；
未映射的字段名直接按 dot path 使用（`engine.go:675-678`）——写规则时字段
路径以 [events.md](events.md) 为准。

### 求值与热重载

- **OS 过滤**：`product` 与资产 OS 不一致则跳过（Windows 规则不在 Linux
  资产上求值）；资产 OS 未知（空串）时不过滤（`engine.go:466-486`）
- **规则索引**：按 class_uid 分桶 + anyClass 桶（`engine.go:325-337`）
- **热重载**：周期扫描（`RULES_RELOAD_SECONDS` 默认 30s，0 关闭），指纹=
  全部 yml 文件的路径+内容 SHA-256，变化则整体重载、`atomic.Pointer` 原子
  切换；编译失败的规则只跳过该条，不影响旧规则集（`engine.go:399-439`）
- **严重度**：informational1/low2/medium3/high4/critical5，默认 3
  （`engine.go:130-132`）
- **ATT&CK 标签**：解析 Sigma `tags` 的 `attack.` 前缀，技术匹配
  `^t\d{4}(\.\d{3})?$`，14 个战术按杀伤链排序（`attack.go:11-79`）

### 规则校验工具

- `go run ./cmd/sigmacheck --strict ../rules`：自带规则必须全部可加载
- `go run ./cmd/detectcheck --strict`：`validation/` 语料回放过引擎，
  命中规则的 ATT&CK 标注必须与技术一致（检测能力回归的核心防线）
- `DATABASE_URL=<只读副本> go run ./cmd/backtest -days 3 <规则目录>`：用近 N 天的真实事件回放规则，
  按规则报告每天命中次数、涉及主机与样本。新规则上线前必须回测：一天响几百次的不是检测能力，是噪音。
  按小时分段读取（只读副本上的长查询会和 WAL 回放冲突被取消），平台指令拉起的事件不计
- `DATABASE_URL=<只读副本> TEMPORAL_RULES_PATH=<时序规则目录> go run ./cmd/backtest -from <RFC3339> -to <RFC3339> <基础规则目录>`：
  时序规则回测，按事件时间顺序回放基础匹配与时序求值（纯内存，只读事务），输出每条时序规则的命中次数、
  按资产 / 账号的分布与样例证据事件 ID，以及未参与求值的覆盖缺口计数，见 [时序检测](temporal-detection.md#回测)
- SigmaHQ 社区规则：`rules/sigmahq/` 收录 Linux 进程 / 文件 / 网络与 DNS 规则（131 条，DRL 1.1），
  引入前在生产数据上回测，低价值高频与误报的列在 `excluded.txt` 不引入；同步方式见该目录 README。
  社区规则的许可要求基于命中的消息保留作者：告警、事件、报告、通知、规则页都带规则作者
- 对 SigmaHQ 全库实测（2026-10）：Linux 211 条可加载 211 条；Windows 2420 条可加载 2180 条，
  其余是 PowerShell 脚本 / 模块、命名管道等未接的数据源

## 威胁情报（`server/internal/intel`）

- **IOC 类型**：`ip / domain / hash` 三类（`ent/schema/intel.go:23`）。
  无独立 JA3 类型，但事件提取时 `ja3_hash` 键归入 hash 碰撞，JA3 实际
  走 hash 通道（`store.go:208`）
- **事件侧提取**：不枚举字段路径，按键名递归收集——`ip`→IP（含 DNS 应答
  `answers[].ip`）；`hostname`/`sni`→域名（小写、去尾点）；
  `sha256/sha1/md5/hashes/hash/ja3_hash/ja3s_hash`→哈希（`store.go:189-211`）
- **匹配**：内存索引 `kind:value`；域名**逐级后缀碰撞**
  （`a.b.evil.com` 依次试 `a.b.evil.com / b.evil.com / evil.com`），
  所以 `evil.com` 能撞上 `c2.evil.com` 的 DNS 查询、TLS SNI、HTTP Host
  （`store.go:137-147`）
- **命中产物**：`rule_id = "intel:<kind>:<value>"`，严重度取 IOC 的
  severity，与规则命中**走同一条**抑制/去重/关联/研判链路——没有第二套
  告警逻辑，抑制规则也能压情报误报（`store.go:23-29,131-135`）
- **有效期与计数**：`expires_at` 过期即跳过；命中计数内存攒批回写
  `matched_count`/`last_matched_at`；周期 reload（`INTEL_RELOAD_SECONDS`
  默认 30s），API 增删后立即 reload（`store.go:127,154-180`）
- **导入**：`detectKind` 自动识别——IP 字面量→ip；32/40/64 位十六进制
  →hash；其余→domain；重复条目跳过（`api/intel.go:205-214`）
- **订阅**（`intel/feeds.go`）：内置 `Catalog` 四个公开源（Feodo / ThreatFox /
  URLhaus / ET compromised），开关存 `settings.intel_feeds`（从未保存过时全开），
  同步结果存 `settings.intel_feed_status`。`RunLeader("intel-feeds")` 启动即同步、之后
  每 `INTEL_FEED_INTERVAL_HOURS`（默认 6）小时一次；控制台改开关或「立即同步」走同一
  `Sync`，以 `WithLock("intel-feeds-sync")` 串行。条目以 `source=feed:<id>` 一条
  `INSERT … ON CONFLICT (kind,value) DO UPDATE … WHERE source LIKE 'feed:%'` 批量写入，
  手工情报不被覆盖；有效期为周期的 8 倍，源里撤下的条目到期失效、拉取暂时失败不断情报；
  关掉的源立即删除，过期订阅条目每次同步清理。外部数据不可信：内网/保留地址剔除，域名与
  哈希逐条校验，源内去重，单源 50 MiB / 10 万条封顶；源返回零条视为异常而非全部撤销。
  ThreatFox 的 `url` 只取主机为 IP 的，避免公共平台主机名误伤。情报列表接口默认不含
  订阅条目，订阅状态与命中过的订阅情报走 `/api/intel/feeds`

## 持久去重（`server/internal/ingest`）

- 状态表 `alert_dedup_state(fingerprint, alert_id, first_ts, last_ts)` 由所有
  worker 共享；不再随 agent 重连或 server 重启丢失。
- 窗口 `ALERT_DEDUP_WINDOW_MINUTES` 默认 5 分钟，以**首条命中时间**为锚，
  窗口不滑动续期。
- **指纹构成**（按接入路径不同）：
  - agent：`ruleID`；文件事件（1001）追加 `|file.path`；爆破合成告警
    `xdr:bruteforce-success|username`（`agent.go:218-232,257`）
  - sensor：`ruleID|assetID`，无资产时 `ruleID|srcIP`（`sensor.go:104-106`）
  - syslog：`ruleID|origin`（`syslog/server.go:203`）
- 同一 fingerprint 先取得 PostgreSQL transaction advisory lock；窗内重复
  原子 `count+1` 并推进 `last_ts`，新窗口新建告警并替换状态指针。
- 事件插入、规则/情报告警和去重状态在同一事务提交。队列重投先被事件主键
  拦住，不会重复增加告警计数。

## 抑制（`server/internal/suppress`）

- 维度：(rule_id, asset_id?) 加可选的**字段条件**（最多 3 条、AND）；asset_id 为空=全局。
  条件按事件体 dot path 取值比较（equals / contains / endswith，不区分大小写），只压掉字段对得上的命中，
  比如 DNS 服务器上只压某个域名，而不是把管着全网查询的整条规则压掉（`suppress/conditions.go`）
- 命中检查有效期 + 资产限定；`expiresInDays` 0=长期（`store.go:86-106`）
- **从不静默**：被压次数持续累计（内存攒批回写 `matched_count`），
  清单里可见、随时可撤销；新建/删除立即 reload 生效
  （`store.go:108-137`、`api/suppressions.go:86-113`）
- 适用点：三条接入路径建告警前，以及 UEBA 与爆破合成告警
  （`ueba/engine.go:159`、`agent.go:256`）
- 抑制先于去重——被压掉的命中不占去重槽位（`agent.go:228-235`）
- **AI 提议、人批准**：AI 用 `suppress` 工具提交抑制草案（状态 `proposed`，不进索引）。只能针对本组单台主机、
  这台主机近 30 天真实命中过的规则（平台指令触发的不算），**必须带字段条件**且要对得上其中至少一次命中的事件，
  理由必填，有效期 1–90 天；条件相同的生效或待批抑制不重复提，30 天内被拒过的同样条件不再接受。主机所在组的管理员在抑制页批准（有效期从批准时重新算，立即生效）或拒绝，
  与命令审批同一档权限，写审计；侧栏显示待批数量

## 爆破得手升级（`internal/ingest/processor.go` 与旧接入路径 `internal/grpcsvc/bruteforce.go`）

- 每条 class 3002 且 `status_id=1` 的成功登录事件触发回查：同资产同用户
  前 **10 分钟**内失败（status_id=2）≥ **5 次**则合成 critical 告警。窗口按事件时间为
  `[成功时间−10分钟, 成功时间)`；同一时间戳不证明先后顺序，成功之后的失败不参与计数。
- 合成告警 `rule_id = "xdr:bruteforce-success"`，severity=5，指纹按
  username 去重，可抑制（`agent.go:250-269`）
- 设计取舍：成功登录稀少，回查一次库即可，无需引擎状态；Linux/Windows
  通用（两侧 3002 同构）。生产事务处理器在失败日志迟到时，还会回看该失败之后十分钟内已入库的成功登录；
  命中仍绑定成功事件及其原始时间，按同资产、同用户名隔离。旧的无事件总线 gRPC 路径仅在成功时回查。
- 生产路径在写入认证事件前获取同资产/用户名的 PostgreSQL 事务锁，避免并发事件互相不可见。
  `temporal_matches` 以规则和成功事件 ID 唯一记录已消费命中，和事件、告警在同一事务提交；
  后续补传不会再次增加同一成功事件的告警计数。被抑制的命中同样记录为已消费。
- 回看依赖数据库仍保留的事件；清理过的失败证据不能恢复。命中记录随成功事件删除级联清理，不能单独清空。
  旧版已合并告警没有保存全部成功事件 ID，升级前历史告警的命中记录迁移仍待补齐，不能据此承诺跨旧版升级完全去重。
  此实现仍是固定爆破检测，不代表已有通用计数/序列规则引擎。

## 平台指令触发的告警（`server/internal/cmdorigin`）

平台自己下发的指令（人工或 AI 的 exec）在主机上跑巡检、取证命令，常常命中侦察、端口探测之类的规则——
上线初期近一半告警来自这里。这类告警来源已知，单独处理：

- agent 拉起指令时设置环境变量 `OPENXDR_COMMAND_ID`，进程采集只认 **agent 直接子进程**上的这个变量
  （别的进程自己设没用），后代沿进程血缘继承；进程、网络、DNS 事件带 `platform_command.uid`。Windows 读不到
  别的进程的环境变量，暂不打标
- server 不盲信标记：指令必须是发给这台资产的 exec，事件发生在指令执行期间（结束后再给后代进程 1 小时）。
  核对不上的标记当没有，照常告警
- 核对通过的告警带 `command_id`、单独去重（不和同规则的真实命中合并），不进关联与研判、不计入态势统计；
  在资产详情的指令列表里按规则汇总显示。查询视图 `alerts` 带 `command_id`，AI 统计威胁时排除
- 指令拉起的进程不进 UEBA：既不学进基线，也不报首次出现——AI 跑过一个新程序，不该让以后别人再跑它时变成「见过的」

## 关联（`server/internal/correlate`）

周期批处理：`CORRELATE_INTERVAL_SECONDS` 默认 10s，每批最多 500 条未归属
告警按 ts 升序（`engine.go:53-63`）。

**归属判定优先级**（`engine.go:83-94`）：

1. **进程血缘**：沿 `parent_process_guid` 上溯最多 16 层，找祖先进程触发的、
   已归属 open/triaged incident 的告警——最强信号，能跨时间窗
   （`engine.go:23,149-182`）
2. **批内同资产缓存**
3. **同资产时间窗**：`CORRELATE_WINDOW_MINUTES` 默认 30 分钟，含"无资产"
   桶（`engine.go:71-77,216-237`）
4. **横向移动**：只在本机没有归属故事时才查——时间窗内别的主机有
   conn_tuple 目的端是本机 IP 的会话事件，归并进对端 incident（每 IP 取
   最近 5 条），避免把巧合的网络连接当成攻击路径（`engine.go:184-214`）

其他行为：

- **无按用户维度的关联**（无此实现）
- **事件图**：存 incidents.graph JSONB；节点类型 asset/alert/process/
  connection，边 rel：hosts/triggered/spawned/lateral；上限
  `CORRELATE_MAX_GRAPH_NODES` 默认 500，触顶只累 overflow
  （`graph.go:5-25`、`engine.go:121-126,239-319`）
- **重开**：triaged 的 incident 收到新告警重开为 open，等重新研判
  （`engine.go:110-137`）
- incident 标题：`"<规则标题> @ <hostname>"`（`engine.go:96-108`）

## UEBA 首次出现（`server/internal/ueba`）

- **只做"新进程首次出现"一种**（包注释 `engine.go:1-6`）；外连侧的规律外联由下面的外联心跳检测负责
- 基线表 `process_baselines`：`(asset_id, exe_path)` 唯一
  （`ent/schema/processbaseline.go:18-27`）
- 扫描：只扫 class 1007 且有资产的事件，游标按 ts 推进每批 1000 条；
  空表从现在开始，**不回放历史**（`engine.go:24-88`）
- 学习期 `UEBA_LEARNING_DAYS` 默认 7 天，按资产从**该资产基线最早
  first_seen** 起算——新资产、新部署、重启都先安静学习，无需额外状态
  就避开告警风暴（`engine.go:126-158`）
- 合成告警 `xdr:new-process`，severity=2，进关联管道、可被抑制
  （`engine.go:159-168`）

## 外联心跳（`server/internal/beacon`）

C2 心跳的样子是同一进程隔着差不多的时间反复连同一个公网目的地。**只看规律会被淹没**：
生产两台主机一天就有一百七十多条规律的公网外联（grafana.com 每 10 分钟、NTP、tailscale、自家 git），
所以检测的是**新出现的**规律外联：

- **判定规律**（`beacon.go` 的 `Periodic`）：最近 `BEACON_WINDOW_HOURS`（默认 12）小时内至少 8 次连接、
  跨度至少 1 小时，间隔中位数在 50 秒到 90 分钟之间，四分位距 ÷ 中位数 ≤ 0.2。只看公网目的地，
  平台指令拉起的连接不算。agent 同一目标 60 秒只报一次连接（`netwatch.rs` 的 `ConnSampler`），
  比这更密的连接看起来都像每分钟一次；周期长于 90 分钟的在窗口里凑不够次数——这两头看不到。
- **身份是（资产, 容器, 进程, 目的端口）**，目的地址与域名只写进告警详情：中继服务换着地址连、
  同一目的地有时带域名有时不带，按地址认每天多出十几条「新心跳」，按进程与端口认只剩几条（生产 7 天数据离线模拟）。
  **已知缺口**：注入进本来就规律连同一端口的进程（比如往一直连 443 的 node 里塞 C2）看不出来；
  新落地的程序、老程序连新端口都能抓到。
- **基线** `beacon_baselines`：`(asset_id, flow)` 唯一，见过即不再报。学习期 `BEACON_LEARNING_DAYS`（默认 7）
  按**资产接入时间**（`assets.first_seen`）算，不按基线最早一条——平时没有规律外联的干净主机进不了基线，
  它冒出的第一条心跳恰恰最可疑。
- **首次启用**（基线为空）回放库里学习期内的历史，只学不报，有历史的资产上线即可检测；之后重启从一个窗口之前接着看，
  重复的由基线唯一索引挡住。单活运行（`cluster.RunLeader`），增量游标 `(ts, id)`，内存只留窗口内的连接时刻。
- 告警 `xdr:beacon`，severity=3，`count` 为窗口内连接次数，`detail` 写一行依据（谁、约多久一次、连哪、几次、离散度），
  研判上下文、事件页与 Pi 只读视图都看得到；可被抑制。`BEACON_ENABLED=0` 关闭。

## AI 研判（`server/internal/triage`）

未配置 `AI_MODEL` 则整个研判不启动（`engine.go:45-48`）。

### 研判流程

- 周期轮询 `AI_INTERVAL_SECONDS` 默认 30s，每批最多 5 个 open incident
  （`engine.go:63-72`）
- **主动调查式**：模型可调用三个有边界的调查工具（`tools.go:21-39`）：
  | 工具 | 参数边界 |
  |---|---|
  | `query_events(keyword, hours)` | raw 全文 ILIKE，关键词转义 `% _ \`；hours 默认 24、超界回落；返回最近 15 条 |
  | `process_lineage(process_guid)` | GUID 必须合法 UUID；祖先上溯 10 层、子进程最多 10 条 |
  | `host_alerts(asset_id, days)` | UUID 校验；days 默认 7、>90 回落；最多 20 条 |
- 事件 raw 截断 300 字符；工具错误以 JSON 回给模型不中断
  （`tools.go:41-61,188-199`）
- **最多 6 轮**（`maxToolTurns`，`engine.go:100`）；模型返回无 tool_calls
  即出答案——不支持 tool calling 的模型天然退化为单轮，无需配置
  （`engine.go:109-128`）；轮数用尽收走工具强制收结论（`engine.go:129-135`）
- 上下文：事件图 + 最多 50 条告警（raw 截 500 字符）+ **误报反馈回流**
  （近 90 天同规则被判 false_positive 的案例）（`engine.go:161-252`）
- verdict 格式：`{verdict: malicious|suspicious|benign, confidence 0-100,
  summary, kill_chain[], actions[]}`；解析容错取首个 `{` 到末个 `}`，
  不合法存档 `{"error":"unparseable"}`；结论写 `ai_verdict` 并把状态推进
  triaged（`engine.go:20-32,85-90,146-159`）
- **模型输出视为不可信输入**：刻意不做 NL2SQL——工具参数空间受限且已
  转义，模型越不出边界

### LLM 客户端

OpenAI 兼容 chat completions；默认 `http://localhost:11434/v1`（Ollama），
temperature 0.1，超时 `AI_TIMEOUT_SECONDS` 默认 120s
（`llm.go:12-29,70-111`）。推理型模型的 `reasoning_content` 不影响解析，
引擎只取 `content` 里的 JSON。推理服务在内网时注意 `NO_PROXY`——Go 默认
读 `HTTP_PROXY`，内网端点可能被错误代理。

### 准确度（`server/internal/api/accuracy.go`）

研判结论落库时记下当次用的模型（`ai_verdict.model`，`triage/engine.go` 的 `withModel`），
控制台「系统设置 → 研判准确度」拿已结案事件对照 AI 结论：

- **只有人写了理由的结案算独立复核**。一键采纳 AI 研判或结案建议（`resolution_source` 非空）、
  系统自动结案（`resolved_by=system`）的结论就是 AI 的结论，只计数、不进比例，否则准确率会被自己抬高。
  早期版本结案不记时间与结案人，那时只有人能结案，按独立复核算，时间取事件创建时间。
- **漏判率** = AI 判良性的事件里，人认定属实（closed）的比例——回答「AI 说良性时能不能信」，
  决定能否让 AI 结更多的案。**误判率** = AI 判可疑或恶意的事件里，人认定误报（false_positive）的比例。
- 按研判模型、按规则分别统计；一个事件带多条规则时每条规则各算一次。没记录模型的旧结论单独成组。
- 比例旁边同时给分子分母，独立复核少于 20 个时界面提示只作参考。

## 响应处置（`server/internal/response`）

**这是系统中唯一能影响被监控主机的功能。**

### 链路

```
POST /api/commands → Hub.Issue 落 command 行并发往 agent 指令通道
  → gRPC 双向流 Commands → agent 执行（respond/ 模块）
  → CommandResult 回传 → Hub.Complete 回写 succeeded/failed/unsupported
```

指令种类：`kill_process`、`isolate_host / unisolate_host`、`exec`，以及带目标（`target`）的三对：

| 动作 | 目标 | Linux | Windows |
|---|---|---|---|
| `block_network / unblock_network` | IP、网段或域名（域名在 agent 上解析） | nftables 独立表 `openxdr_block`，集合元素带原始目标注释，进出都丢 | 防火墙规则组「OpenXDR Block」，进出各一条；防火墙未启用时报失败 |
| `quarantine_file / restore_file` | 文件绝对路径 | 移进状态目录 `isolated-files/`（0700，文件去掉全部权限），记原路径、大小、SHA-256、权限与属主 | 同左，`ProgramData\OpenXDR\state\isolated-files` |
| `disable_account / enable_account` | 本机账号名 | `usermod -L -e 1`：锁密码并置过期，公钥登录经 PAM 账户检查同样被挡 | `Disable-LocalUser`（只管本地账号，域账号在域控处理） |

目标先经 server 的 `response.NormalizeTarget` 校验，agent 收到后再按同样的规则查一遍（`respond/netblock.rs`、
`quarantine.rs`、`account.rs`）：封锁拒绝覆盖 server 自己的地址（server 侧取 `ISOLATION_ALLOW`，agent 侧取
`OPENXDR_SERVER` 解析结果）、回环、未指定地址和过宽的网段（IPv4 宽于 /16、IPv6 宽于 /48）；隔离文件只处理普通文件，
拒绝伪文件系统、agent 自身与它的状态目录，恢复时原位置已有文件拒绝覆盖；锁定账号拒绝 root、Administrator、SYSTEM
这类内置账号、uid 0 与 agent 自身运行的账号。已有会话不随账号锁定断开，要断开用结束进程或隔离主机。
旧版 agent 不认识新动作，回执「未指定动作」失败，不会误执行（`hub.go`、`api/commands.go`、`grpcsvc/commands.go`）。

### 闸门与防护（改这块代码时全部不得绕过）

指令一律真执行，没有演练模式。两道闸门：

1. **全局开关** `RESPONSE_ENABLED`，否则一律拒绝下发（`hub.go:35-40,75-77`）
2. **隔离自保**：未配置 `ISOLATION_ALLOW` 时 agent 拒绝隔离——隔离后收不到
   解除指令只能人工上机；隔离指令自动附带放行清单
   （`main.go:203-211`、`api/commands.go:73-76`）

结构性防护：agent 不在线即失败不攒指令；每 agent 通道缓冲 32 条满即失败；
断线重连不自动重放任何旧指令，迟到回执仍可更新结果；指令流冒领防护 `verifyAgentID`；结果回写必须对上
库里的 command_id（`hub.go:25-215`、`grpcsvc/commands.go:29-44`）。

### 自动响应保险（`response/auto.go`）

挂 `OnVerdict` 钩子，verdict=malicious 且 confidence ≥
`AUTO_RESPONSE_MIN_CONFIDENCE`（默认 90）时触发：

1. `AUTO_RESPONSE_ENABLED=true` 才挂钩子，隔离真执行，仍受 `RESPONSE_ENABLED` 约束
2. `AUTO_RESPONSE_EXEMPT` 主机名白名单绝不隔离，跳过也记审计
3. 每次决策（含跳过）落审计

同一 incident 同一资产只自动隔离一次（查 issued_by="auto" 的 isolate_host），
重开重判不重复隔离（`auto.go:28-104`）。

## 通知（`server/internal/notify`）

- 推送目标存 `settings` 表的 `notify` 键，控制台「系统设置 → 通知」可改并发送测试；
  从未保存过时用 `WEBHOOK_*` 环境变量（`notify/settings.go`）。未配置目标时通知器空转，
  配置后只推之后的事件
- 格式：generic 推 Message JSON；dingtalk/wecom 为 `{"msgtype":"text",...}`；
  feishu 为 `{"msg_type":"text",...}`；正文模板共用（`notify.go:144-227`）
- **投递语义**：AI 启用时等 verdict 再推；benign 静默跳过，但最高级别 ≥ 高危(4)
  的照推并标「良性，但级别高需人工复核」——AI 会看错，高危事件不能被一句良性吞掉；
  closed/false_positive 不推；目标启用前的历史事件不补发；失败下周期重试；
  每批 20 个（`notify.go:73-137`）
- 阈值 `WEBHOOK_MIN_SEVERITY`（默认 0=全推），按 incident 内告警最高
  severity 过滤（`notify.go:98-103,156-168`）
- 主机失联（`server/internal/liveness`）：agent 指令通道在线时每分钟刷新 `last_seen`；
  超过 `AGENT_SILENT_MINUTES`（默认 10）没有心跳推一次「N 台主机失联」，恢复推一次
  「N 台主机恢复」，同一次失联只推一次（`assets.silent_since`）。巡视器启动后先等满
  该时长再判定，避免 server 重启期间把整片主机报成失联

## 数据保留（`server/internal/janitor`）

- `RETENTION_DAYS` 默认 30 天，0=不清理；周期 `RETENTION_INTERVAL_MINUTES`
  默认 60 分钟（`janitor.go:28-30`）
- 只删**未被任何告警引用**的过期事件（`event.Not(event.HasAlerts())`）——
  证据跟着 incident 的生命周期走；每批 10000 条批间让出 100ms；同周期
  顺带清过期会话（`janitor.go:19,46-83`）

## 认证、RBAC 与审计

- **认证**：不透明随机 token，库中只存 SHA-256，cookie `openxdr_session`
  （HttpOnly、SameSite=Lax），TTL 7 天；删行即吊销
  （`auth/auth.go:27-32,116-186`）
- 登录 bcrypt 校验，用户不存在用 dummy hash 陪跑防时间侧信道；同 IP 失败
  5 次起 30s 指数退避、封顶约 64 分钟（`auth/throttle.go:12-59`）
- 初始 admin 密码取 `ADMIN_PASSWORD`，未配置则随机生成打印一次
  （`auth.go:60-87`）
- **RBAC 矩阵**（`minRole`，`auth.go:41-50`）：
  | 端点 | 最低角色 |
  |---|---|
  | `/api/users*`、`/api/audit` | admin |
  | 所有 GET | viewer |
  | 其余写操作（POST/PUT/DELETE） | analyst |
- **审计**字段：username/remote_addr/action/target/detail；写失败只记日志
  不阻断（`audit/audit.go:39-53`）。action 全清单：`login / login_failed /
  login_throttled / logout / incident_status / command_issued /
  suppression_created / suppression_deleted / intel_created /
  intel_imported / intel_deleted / intel_feeds_updated / intel_feeds_synced / agent_config_set / user_created /
  user_deleted / password_reset / auto_response / auto_response_skipped /
  auto_response_failed`

## server 环境变量全清单（`server/main.go`）

| 变量 | 默认值 | 用途 |
|---|---|---|
| `DATABASE_URL` | `postgres://openxdr:openxdr@localhost:5432/openxdr?sslmode=disable` | Postgres 连接 |
| `NATS_URL` | 空（单机直连） | NATS 集群地址；配置后启用 JetStream |
| `QUEUE_SHARDS` | `32` | 按 partition_key 一致性分片数 |
| `QUEUE_REPLICAS` | `1` | JetStream stream 副本数 |
| `QUEUE_MAX_BYTES_GB` / `QUEUE_MAX_AGE_HOURS` | `20` / `0` | 容量满时拒收新消息，时间必须为 0（不自动过期） |
| `LOG_FORMAT` / `LOG_LEVEL` | text / info | 结构化日志格式与等级 |
| `HTTP_ADDR` / `GRPC_ADDR` | `:8080` / `:8081` | REST / gRPC 监听 |
| `TLS_CA_FILE` / `TLS_CERT_FILE` / `TLS_KEY_FILE` | 空 | gRPC mTLS，三者必须同配否则启动报错；全空=明文（仅本机调试） |
| `ADMIN_PASSWORD` | 空（随机生成打印一次） | 初始 admin 密码 |
| `RULES_PATH` | `../rules` | Sigma 规则目录 |
| `RULES_RELOAD_SECONDS` | `30`（0 关闭） | 规则热重载扫描周期 |
| `ALERT_DEDUP_WINDOW_MINUTES` | `5` | 告警去重窗口 |
| `SUPPRESSION_RELOAD_SECONDS` | `30` | 抑制重载/计数回写周期 |
| `INTEL_RELOAD_SECONDS` | `30` | 情报重载/计数回写周期 |
| `CORRELATE_WINDOW_MINUTES` | `30` | 关联时间窗 |
| `CORRELATE_INTERVAL_SECONDS` | `10` | 关联批次周期 |
| `CORRELATE_MAX_GRAPH_NODES` | `500` | 事件图节点上限 |
| `UEBA_LEARNING_DAYS` | `7` | 首次出现检测学习期 |
| `UEBA_INTERVAL_SECONDS` | `30` | UEBA 批次周期 |
| `BEACON_ENABLED` | `1` | 外联心跳检测开关，0 关闭 |
| `BEACON_LEARNING_DAYS` | `7` | 外联心跳按资产接入时间的学习期 |
| `BEACON_WINDOW_HOURS` | `12` | 判定规律看的时间窗 |
| `BEACON_INTERVAL_SECONDS` | `300` | 外联心跳批次周期 |
| `RETENTION_DAYS` | `30`（0 不清） | 原始事件保留期 |
| `RETENTION_INTERVAL_MINUTES` | `60` | 清理周期 |
| `SYSLOG_ADDR` | 空（不启用） | syslog UDP+TCP 监听 |
| `AI_MODEL` | 空（不启用） | 研判模型名 |
| `AI_BASE_URL` | `http://localhost:11434/v1` | OpenAI 兼容端点 |
| `AI_API_KEY` | 空 | Bearer key |
| `AI_TIMEOUT_SECONDS` | `120` | LLM 超时 |
| `AI_INTERVAL_SECONDS` | `30` | 研判批次周期 |
| `RESPONSE_ENABLED` | `false` | 响应处置总开关 |
| `ISOLATION_ALLOW` | 空（隔离将被 agent 拒绝） | 隔离放行地址，逗号分隔 |
| `AUTO_RESPONSE_ENABLED` | `false` | 自动响应钩子，开启即真实隔离（依赖 RESPONSE_ENABLED） |
| `AUTO_RESPONSE_MIN_CONFIDENCE` | `90` | 自动隔离置信度门槛 |
| `AUTO_RESPONSE_EXEMPT` | 空 | 自动隔离主机白名单 |
| `WEBHOOK_URL` | 空（不启用） | 通知地址 |
| `WEBHOOK_FORMAT` | `generic` | generic / dingtalk / feishu / wecom |
| `WEBHOOK_INTERVAL_SECONDS` | `30` | 通知扫描周期 |
| `WEBHOOK_LINK_BASE` | 空 | 控制台链接前缀 |
| `WEBHOOK_MIN_SEVERITY` | `0`（全推） | 通知最低严重度（1 信息 ~ 5 严重） |

采集端环境变量见 [collection.md](collection.md)（agent 与 sensor 各一张表）。
