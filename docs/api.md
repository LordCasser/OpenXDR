# REST API 参考

Base: `http://<server>:8080`。除 `POST /api/login` 外全部需要会话 cookie
（`openxdr_session`）。权限约定：**GET = viewer 及以上，写操作 = analyst 及以上，
`/api/users`、`/api/audit`、`/api/settings` 与 `/api/groups` 写操作 = admin**。

## 认证

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/login` | `{"username","password"}` → 设置会话 cookie。失败按源 IP 指数退避 |
| POST | `/api/logout` | 吊销当前会话 |
| GET | `/api/me` | 当前用户 `{username, role}` |

## 事件与告警

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/incidents?status=&assetId=&limit=&offset=` | incident 列表（按创建时间倒序），含派生严重度、告警数与 `groupId`（第一条有资产的告警所在资产的组，无则 null）；`status` 另支持 `unresolved`（= open + triaged）与 `review`（需人工复核：未结案，且 AI 未判良性或最高告警级别 ≥ 4，与 Webhook 推送同一口径）；`limit` 默认 50、范围 1..500，`offset` 默认 0；响应头 `X-Total-Count` 为分页前的匹配总数；`assetId` 筛涉及该主机的事件 |
| GET | `/api/incidents/{id}` | 详情：实体图、告警明细（含原始事件）、AI verdict、`groupId` |
| POST | `/api/incidents/{id}/status` | `{"status":"open\|closed\|false_positive","note":"…"}`；closed 为属实已处置、false_positive 为误报或良性，两者必须写 `note`（1–2000 字），记录结案人与时间并作为案例喂回研判；改回 open 清掉结案信息 |
| GET | `/api/findings?status=` | 运维待办（巡检 AI 登记，按组裁剪，最近 500 条），含主机名、首次与最近发现时间 |
| POST | `/api/findings/{id}/status` | `{"status":"open\|resolved\|ignored","note":"…"}`，需组内 analyst；resolved / ignored 必须写原因，忽略原因会交给巡检 AI，之后不再登记 |
| GET | `/api/incidents/{id}/report` | 事件报告（Markdown 附件下载）：判定、攻击链、涉及实体、告警时间线、处置记录、处置建议 |
| GET | `/api/events` | 原始事件检索，参数见下 |
| GET | `/api/events/{id}/related` | 与这条日志有确定关联的日志，按关联方式分组：ancestor 父进程链 / process 同一进程 / child 子进程 / connection 同一连接 / peer 别的主机连同一远端 / nearby 同主机前后两分钟；只取调用者可见的资产 |
| POST | `/api/events/{id}/explain?lang=&refresh=` | 问 AI（analyst）：发起后台解读并立即返回任务 `{id,status,result,error}`。模型读这条日志与上面的候选，`result` 含判定（benign / suspicious / malicious / unknown）、结论、依据、下一步，以及从候选里挑出的相关日志。已有在跑的或已有结果时直接返回它，`refresh=1` 才重新解读；未配置研判与标注模型时 503 |
| GET | `/api/events/{id}/explain?lang=` | 读自己对这条日志的最近一次解读：`status` 为 none / running / done / failed；前端在 running 时轮询。解读按发起人存，保留 7 天 |
| GET | `/api/stats` | 概览：24h 降噪漏斗、告警趋势、按级别的告警分布（`alertsBySeverity`）、Top 规则、资产在线率；`reviewIncidents` 为需人工复核的事件数（口径同 `status=review`） |
| GET | `/api/rules` | 引擎当前加载的规则（热重载后即时反映），含数据源覆盖标记与 ATT&CK 标签 |
| GET | `/api/attack` | ATT&CK 覆盖矩阵：按杀伤链顺序的战术列与技术格，含未打标签、无数据源的规则数 |
| GET | `/api/temporal-gaps?assetId=&from=&to=&limit=` | 该资产的时序检测缺口（`candidate_limit` / `late`），详见 [时序检测](temporal-detection.md#缺口查询接口) |
| GET | `/api/temporal-rule-snapshots?limit=&alertId=` | 已归档的时序规则版本（**全局 admin / analyst**，角色每次从库里取），按首次使用时间倒序：`{items:[{revision,createdAt,format,baseRuleCount,temporalRules}],truncated}`；`limit` 默认 20、范围 1..100。带 `alertId` 时只返回该告警命中时的版本（单事件告警、旧版本告警或调用者看不到的告警返回空列表） |
| GET | `/api/temporal-rule-snapshots/{revision}?rule=` | 按版本哈希取当时的时序规则：`{revision,createdAt,rules:[{id,title,author,kind,groupBy,severity,windowSeconds,threshold,references,source,base}]}`，`base` 为该规则引用的基础规则原文；`rule` 只取一条（不存在 404）。按原文重算版本哈希，归档被改动或格式不支持时 500 拒绝展示。权限同上 |

`GET /api/events` 参数：`from`/`to`（RFC3339，默认近 24h）、`assetId`、
`classUid`（1001 文件 / 1007 进程 / 3002 认证 / 4001 网络 / 4003 DNS /
201002 注册表 / 100001 日志）、
`source`（agent/sensor/syslog）、`q`（对事件体子串匹配，通配符按字面量处理）、
`limit`（≤200，默认 100）。返回条数等于 `limit` 时带响应头 `X-Truncated: 1`，
提示可能还有更多、应收窄条件。各类事件的字段 schema 见
[events.md](events.md)。

## 威胁情报

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/intel` | IOC 清单（含命中计数） |
| POST | `/api/intel` | 单条：`{"kind":"ip\|domain\|hash","value","source","severity","note","expiresInDays"}`，kind 缺省自动识别 |
| POST | `/api/intel/import` | 批量：`{"text":"一行一条","source","severity","expiresInDays"}`，类型自动识别，重复跳过，`#` 行忽略 |
| DELETE | `/api/intel/{id}` | 删除 |
| GET | `/api/intel/feeds` | 情报订阅：`{feeds:[{id,name,url,severity,enabled,count,hits,syncedAt,error}], hits:[命中过的订阅情报], intervalHours}`。`/api/intel` 列表不含订阅条目 |
| PUT | `/api/intel/feeds` | `{"enabled":["feodo",...]}` 保存开关并立即同步（admin） |
| POST | `/api/intel/feeds/sync` | 立即同步（admin） |

## 误报抑制

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/suppressions` | 抑制清单（含压掉次数）；非 admin 只见本组资产的抑制，全局抑制仅 admin 可见 |
| POST | `/api/suppressions` | `{"ruleId","assetId"(空=全局),"reason","expiresInDays"(0=长期)}`；需该资产所在组的 analyst，全局抑制仅 admin，否则 403 |
| DELETE | `/api/suppressions/{id}` | 撤销，权限同创建（按该抑制的资产判断） |

## 响应处置

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/commands?incidentId=&assetId=` | 指令历史，可按事件或主机筛选 |
| POST | `/api/commands` | `{"kind":"kill_process\|isolate_host\|unisolate_host\|exec\|block_network\|unblock_network\|quarantine_file\|restore_file\|disable_account\|enable_account","assetId","incidentId","pid","target"}`（一律真执行，没有演练模式）；封锁、隔离文件、锁定账号必须带 `target`（IP / 网段 / 域名、文件绝对路径、账号名），不合法或会封到 server 自己时 400；`exec` 另带 `"cmd"`（必填）与 `"timeoutMs"`（0 = agent 默认 60s），结果回写 `exitCode` / `stdout` / `stderr` / `truncated`（各截断到 64KB） |

需 server 配置 `RESPONSE_ENABLED=true`；隔离要求 `ISOLATION_ALLOW` 包含 server
的 gRPC 端点，否则 agent 拒绝执行。

## 资产与管理

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/assets` | 资产清单（含 `groupId`，未分组为 null；`agentVersion` 为 agent 自报版本） |
| GET | `/api/assets/{id}/config` | 该主机的采集配置 |
| PUT | `/api/assets/{id}/config` | 设置采集配置：`{"fileWatchDirs":[...],"collectFiles":true,"collectAuth":true,"collectPersist":true,"collectNetwork":true,"collectInventory":true,"collapsePeriodic":true}`。随 agent 下次注册（重连或重启）生效；`collectNetwork` 在 Linux eBPF 与 Windows ETW 路径生效 |
| GET | `/api/assets/{id}/profile` | 资产画像：区域、暴露级别、云环境、监听端口、依赖与 AI 标注。改标注、指派区域与资产图谱、攻击面、区域定义等接口见 [资产图谱与攻击面](asset-map.md#接口) |
| GET | `/api/users` | 用户列表（admin） |
| POST | `/api/users` | 建号：`{"username","password","role"}`（admin） |
| POST | `/api/users/{id}/password` | 重置密码（admin） |
| DELETE | `/api/users/{id}` | 删号（admin） |
| GET | `/api/audit?q=` | 审计日志（admin，最新 500 条）；`q` 对用户名、动作、对象、详情做不区分大小写的子串匹配；取满 500 条时带 `X-Truncated: 1` |
| GET | `/api/settings/notify` | 通知配置 `{url,format,linkBase,minSeverity}`（admin）。未保存过时返回环境变量默认值 |
| PUT | `/api/settings/notify` | 保存通知配置（admin）；`format` 取 generic / dingtalk / feishu / wecom，地址须为 http(s) |
| POST | `/api/settings/notify/test` | 用请求体里的配置（不保存）发一条测试消息（admin），推送失败返回 502 |
| GET | `/api/setup` | 安装初始化状态 `{agreementVersion,accepted,acceptedBy,acceptedAt,onboarded}`（所有登录用户）。已有组或主机的实例 `onboarded` 恒为 true |
| POST | `/api/setup/agreement` | 管理员同意用户协议 `{version}`，版本须与当前 `agreementVersion` 一致，否则 409；落审计 `agreement_accepted` |
| POST | `/api/setup/onboarded` | 结束首次引导 `{skipped:[...]}`（admin），须先同意协议；落审计 `onboarding_finished` 并记下跳过的步骤 |
| GET | `/api/settings/ai` | AI 与外部情报配置（admin）：端点、研判/标注模型、Pi 模型、反向解析、VT 转情报阈值；密钥只返回是否已设与末四位；`source` 标明每项来自控制台还是环境变量 |
| PUT | `/api/settings/ai` | 修改（admin）：只改出现的字段；密钥传空串表示清空；`reset` 列出的项回到环境变量。未配置 `HOST_CREDENTIAL_KEY` 时拒绝保存密钥 |
| POST | `/api/settings/ai/test` | 用请求体里未保存的值测试（admin）：`target` 为 model / piModel 时发一句最短对话，vt 时查一个公共地址；失败返回 502 |
| GET | `/api/settings/ai/accuracy?days=` | 研判准确度（admin，默认 90 天）：总体、按研判模型、按规则的独立复核数、AI 判良性数与其中的漏判、AI 告警数与其中的误判、采纳 AI 与自动结案数，及最近 10 条漏判与误判。只有人写理由的结案算独立复核 |
| GET | `/api/settings/ai/usage?days=&tz=` | AI 用量（admin）：按天、用途（chat / task / triage / annotate / explain）、模型聚合的 token 与调用次数，及用量最多的 10 个会话 |

## 资产组

一台主机属于至多一个组；用户在每个组内有各自角色（admin / analyst / viewer），
全局 admin 天然是所有组的 admin。实现见 `server/internal/api/groups.go`。

**按组裁剪**：非 admin 用户在资产、事件、告警、incident、指令、采集配置、统计与 incident 报告上
只看得到自己所在组的资产（`server/internal/api/scope.go`）。未分组资产与无归属数据（如 syslog）
只有全局 admin 可见；incident 的全部告警都落在可见资产上才可见，跨组 incident 只有 admin 能看。
写操作在全局角色之外，还要求目标资产所在组内角色达到 analyst，否则 403；读不到的资源一律 404。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/groups` | 当前用户可见的组：`[{"id","name","role","assetCount"}]`，非成员看不到 |
| POST | `/api/groups` | 建组：`{"name"}`（admin） |
| DELETE | `/api/groups/{id}` | 删组：资产退回未分组，成员关系清除（admin） |
| GET | `/api/groups/{id}/members` | 成员名单（组 admin） |
| PUT | `/api/groups/{id}/members/{userId}` | 设定成员角色：`{"role"}`，不存在则添加（admin） |
| DELETE | `/api/groups/{id}/members/{userId}` | 移除成员（admin） |
| PUT | `/api/groups/{id}/assets/{assetId}` | 资产归入该组，离开原组（admin） |
| DELETE | `/api/groups/{id}/assets/{assetId}` | 资产移出该组；不在此组返回 409（admin） |

建组自带 AI 高风险命令名单并自动开通组查询身份；删组一并回收（见 `docs/pi-backend.md`）。

## 主机接入

文档导入、凭据管理和 SSH 纳管接口见 [文档导入与主机纳管](host-enrollment.md#api)。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/enroll-tokens/status` | 在线接入是否可用：`{enabled, reason, platforms}`，`reason` 说明缺什么配置 |
| GET | `/api/enroll-tokens?groupId=` | 本组令牌列表（组 admin），不含明文 |
| POST | `/api/enroll-tokens` | `{"groupId","days"}` 签发令牌（组 admin），`days` 缺省 7、最长 30；明文 `token` 只在此返回一次 |
| DELETE | `/api/enroll-tokens/{id}` | 撤销令牌（组 admin） |

以下端点**免登录**，由安装脚本调用：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/enroll/install.sh` | Linux 安装脚本，参数 `<控制台地址> <令牌>` |
| GET | `/api/enroll/install.ps1` | Windows 安装脚本，参数同上 |
| GET | `/api/enroll/agent/{platform}` | agent 安装包，`linux-amd64` / `linux-arm64` / `windows-amd64` |
| POST | `/api/enroll/register` | `Authorization: Bearer <令牌>`，请求体 `{"hostname","os","csr"}`；返回 `{server, ca, cert}`。令牌无效 401，主机名已有在线 agent 或主机已在别组 409，接入未启用 503 |

## 对接示例：定时同步情报源

```bash
# 登录拿 cookie
curl -c cookie.txt -X POST http://xdr:8080/api/login \
  -d '{"username":"feeds-bot","password":"..."}'

# 把情报源导出的清单灌进去，30 天有效期
curl -b cookie.txt -X POST http://xdr:8080/api/intel/import \
  -H 'Content-Type: application/json' \
  -d "{\"text\": \"$(tr '\n' '\\n' < feed.txt)\", \"source\": \"feed-x\", \"expiresInDays\": 30}"
```
