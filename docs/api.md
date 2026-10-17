# REST API 参考

Base: `http://<server>:8080`。除 `POST /api/login` 外全部需要会话 cookie
（`openxdr_session`）。权限约定：**GET = viewer 及以上，写操作 = analyst 及以上，
`/api/users`、`/api/audit`、`/api/hunt` 与 `/api/groups` 写操作 = admin**。

## 认证

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/login` | `{"username","password"}` → 设置会话 cookie。失败按源 IP 指数退避 |
| POST | `/api/logout` | 吊销当前会话 |
| GET | `/api/me` | 当前用户 `{username, role}` |

## 事件与告警

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/incidents?status=&assetId=` | incident 列表（最新 50 条），含派生严重度与告警数；`assetId` 筛涉及该主机的事件 |
| GET | `/api/incidents/{id}` | 详情：实体图、告警明细（含原始事件）、AI verdict |
| POST | `/api/incidents/{id}/status` | `{"status":"open\|closed\|false_positive"}` |
| GET | `/api/incidents/{id}/report` | 事件报告（Markdown 附件下载）：判定、攻击链、涉及实体、告警时间线、处置记录、处置建议 |
| GET | `/api/events` | 原始事件检索，参数见下 |
| GET | `/api/stats` | 概览：24h 降噪漏斗、告警趋势、按级别的告警分布（`alertsBySeverity`）、Top 规则、资产在线率 |
| GET | `/api/rules` | 引擎当前加载的规则（热重载后即时反映），含数据源覆盖标记与 ATT&CK 标签 |
| GET | `/api/attack` | ATT&CK 覆盖矩阵：按杀伤链顺序的战术列与技术格，含未打标签、无数据源的规则数 |
| POST | `/api/hunt` | 自然语言狩猎：`{"question"}` → `{answer, steps}`。模型用只读调查工具查证后作答，`steps` 是调用过的工具与参数，供复核。未配置 `AI_MODEL` 返回 503 |

`GET /api/events` 参数：`from`/`to`（RFC3339，默认近 24h）、`assetId`、
`classUid`（1001 文件 / 1007 进程 / 3002 认证 / 4001 网络 / 4003 DNS /
201002 注册表 / 100001 日志）、
`source`（agent/sensor/syslog）、`q`（对事件体子串匹配，通配符按字面量处理）、
`limit`（≤200，默认 100）。各类事件的字段 schema 见
[events.md](events.md)。

## 威胁情报

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/intel` | IOC 清单（含命中计数） |
| POST | `/api/intel` | 单条：`{"kind":"ip\|domain\|hash","value","source","severity","note","expiresInDays"}`，kind 缺省自动识别 |
| POST | `/api/intel/import` | 批量：`{"text":"一行一条","source","severity","expiresInDays"}`，类型自动识别，重复跳过，`#` 行忽略 |
| DELETE | `/api/intel/{id}` | 删除 |

## 误报抑制

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/suppressions` | 抑制清单（含压掉次数） |
| POST | `/api/suppressions` | `{"ruleId","assetId"(空=全局),"reason","expiresInDays"(0=长期)}` |
| DELETE | `/api/suppressions/{id}` | 撤销 |

## 响应处置

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/commands?incidentId=&assetId=` | 指令历史，可按事件或主机筛选 |
| POST | `/api/commands` | `{"kind":"kill_process\|isolate_host\|unisolate_host\|exec","assetId","incidentId","pid","dryRun"}`；`exec` 另带 `"cmd"`（必填）与 `"timeoutMs"`（0 = agent 默认 60s），结果回写 `exitCode` / `stdout` / `stderr` / `truncated`（各截断到 64KB） |

需 server 配置 `RESPONSE_ENABLED=true`；隔离要求 `ISOLATION_ALLOW` 包含 server
的 gRPC 端点，否则 agent 拒绝执行。

## 资产与管理

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/assets` | 资产清单（含 `groupId`，未分组为 null；`agentVersion` 为 agent 自报版本） |
| GET | `/api/assets/{id}/config` | 该主机的采集配置 |
| PUT | `/api/assets/{id}/config` | 设置采集配置：`{"fileWatchDirs":[...],"collectFiles":true,"collectAuth":true,"collectPersist":true,"collectNetwork":true}`。随 agent 下次注册（重连或重启）生效；`collectNetwork` 在 Linux eBPF 与 Windows ETW 路径生效 |
| GET | `/api/users` | 用户列表（admin） |
| POST | `/api/users` | 建号：`{"username","password","role"}`（admin） |
| POST | `/api/users/{id}/password` | 重置密码（admin） |
| DELETE | `/api/users/{id}` | 删号（admin） |
| GET | `/api/audit` | 审计日志（admin） |
| GET | `/api/settings/notify` | 通知配置 `{url,format,linkBase,minSeverity}`（admin）。未保存过时返回环境变量默认值 |
| PUT | `/api/settings/notify` | 保存通知配置（admin）；`format` 取 generic / dingtalk / feishu / wecom，地址须为 http(s) |
| POST | `/api/settings/notify/test` | 用请求体里的配置（不保存）发一条测试消息（admin），推送失败返回 502 |

## 资产组

一台主机属于至多一个组；用户在每个组内有各自角色（admin / analyst / viewer），
全局 admin 天然是所有组的 admin。实现见 `server/internal/api/groups.go`。

**按组裁剪**：非 admin 用户在资产、事件、告警、incident、指令、采集配置、统计与 incident 报告上
只看得到自己所在组的资产（`server/internal/api/scope.go`）。未分组资产与无归属数据（如 syslog）
只有全局 admin 可见；incident 的全部告警都落在可见资产上才可见，跨组 incident 只有 admin 能看。
写操作在全局角色之外，还要求目标资产所在组内角色达到 analyst，否则 403；读不到的资源一律 404。
狩猎会读全量数据、无法按组裁剪，只开放给 admin。

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

建组自带只读巡检名单并自动开通组查询身份；删组一并回收（见 `docs/pi-backend.md`）。

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
