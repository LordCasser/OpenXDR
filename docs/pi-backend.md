# Pi 会话与命令审批后端

实现位置：`server/internal/piruntime`、`agentchat`、`commandgate`、`api/agentsessions.go`、
`api/commandpolicy.go`。总体设计见 [AI 原生架构](ai-native.md)，JSONL 细节见
[runner 说明](../server/pi-runtime/README.md)。当前实现是 SDK runner，不是 Pi CLI extension。

## 配置

| 环境变量 | 默认值 | 用途 |
|---|---|---|
| `PI_MODEL` | 空（关闭 Pi 对话） | Chat Completions 模型名，独立于旧 triage 的 `AI_MODEL` |
| `AI_BASE_URL` | `http://localhost:11434/v1` | 与旧 triage 共用模型端点 |
| `AI_API_KEY` | 空 | 模型凭据，仅通过子进程 stdin 传递 |
| `PI_RUNNER_PATH` | `/app/pi-runtime/runner.mjs` | 容器内 runner；本地运行改为绝对路径 |
| `PI_TIMEOUT_SECONDS` | `1800` | 一轮对话总超时，含模型、工具和审批等待 |
| `PI_APPROVAL_TIMEOUT_SECONDS` | `600` | AI 和人工 exec 审批等待上限 |
| `PI_QUERY_DATABASE_URLS` | 空 | JSON 对象：组 UUID → 专属只读 DSN；未配置的组不开放 SQL |
| `RESPONSE_ENABLED` | `false` | 现有响应总开关，exec 同样受其控制 |

Pi 不注册内置文件和 shell 工具，平台只暴露 exec/report，以及已配置组的 query。
没有新增对外工具执行端口，身份、组、来源和 dry-run 均由 Go 绑定，模型不能修改。
每轮上下文包含本组最多 200 台资产的 UUID、主机名和 OS；超出会标注截断。
每轮最多 32 次模型调用，每次输出最多 8192 token。未实现费用预算或自动历史压缩。

## 前端接口

所有请求使用现有会话 cookie 与同源保护。请求字段采用下表的 camelCase；直接返回的
Ent 实体字段采用 snake_case（例如 `group_id`、`dry_run`、`created_at`）。

| 接口 | 请求 | 权限与响应 |
|---|---|---|
| `POST /api/agent-sessions` | `{groupId,title?,dryRun?}` | 组 analyst；创建 idle 会话，默认 dry-run，返回 201 + 实体 |
| `GET /api/agent-sessions?groupId=...` | — | 组 viewer；最近 100 个会话 |
| `GET /api/agent-sessions/{id}` | — | 组 viewer；单个会话状态与元数据 |
| `GET /api/agent-sessions/{id}/messages?afterSeq=0` | — | 组 viewer；seq 升序，每页最多 1000 条，下一页传最后一条 seq |
| `POST /api/agent-sessions/{id}/messages` | `{prompt}` | 发起人且仍为组 analyst；POST SSE |
| `GET /api/agent-reports?groupId=...` | — | 组 viewer；最近 100 个原始 Markdown 报告 |
| `GET /api/agent-reports/{id}` | — | 组 viewer；报告实体 |
| `GET /api/commands/{id}` | — | 资产所属组 viewer；未分组资产仅全局 admin，可查询迟到回执 |
| `GET /api/command-policies?groupId=...` | — | 组 admin；名单 |
| `POST /api/command-policies` | `{groupId,origin,pattern}` | 组 admin；创建名单，返回 201 |
| `DELETE /api/command-policies/{id}` | — | 组 admin；删除，返回 204 |
| `GET /api/approvals?groupId=...` | — | 组 admin；最近 100 个审批（含终态） |
| `POST /api/approvals/{id}/decision` | `{approve:true或false}` | 组 admin；原子决定，返回 204，重复/过期返回 409 |

SSE 用 fetch 读取 POST 响应，不能直接用浏览器 EventSource：

- `session`：`{"id":"..."}`。
- `pi`：runner 原始事件；其中 `type=event` 的 `event` 是 Pi 事件，
  `message_update` 用于逐字显示，`tool_execution_start/end` 用于工具卡片。
- `heartbeat`：每 15 秒保活；代理不要缓存流。
- `done`：`{Response,StopReason,Turns}`，只有数据库终态保存成功后发送。
- `error`：`{"error":"..."}`，流开始后的失败通过此事件报告。

`pi` 内部的 `result` 仅表示模型结束；前端必须等待外层 `done`。
`StopReason=length/max_turns` 表示截断/轮数耗尽，不能展示为完整巡检成功。
客户端断开会终止推理与审批等待，已下发的命令不会因此撤销。
同一会话只允许一个 running 请求；失败会话不自动重试，需检查命令记录后另建会话。
进程异常退出导致遗留 running 状态时，不自动恢复或重放主机操作。

## exec 与审批

`exec` 参数：`{host:资产UUID,cmd:完整命令,timeout?:秒}`，timeout 为 1–300，默认 agent 的 60 秒。
执行只允许当前组资产；等待审批后会再次检查成员角色和资产归组。

- AI：完整命令匹配任一 allow 名单后放行，否则等待审批。空名单意味着全部审批。
- 人工：匹配任一 deny 名单后等待审批，否则放行。空名单意味着没有额外审批。
- origin 固定为入口身份；创建名单时，AI 自动使用 allow，人工自动使用 deny。
- pattern 为 Go 正则，平台强制完整字符串匹配。例如 `whoami` 不匹配 `whoami; id`。
  **这不是 shell AST 解析**；管理员配置 `.*` 等宽泛表达式就会扩大放行范围。
- 名单命中也不会越过组权限、`RESPONSE_ENABLED` 或 dry-run。审批只批准原始资产、
  命令、超时和 dry-run 的组合，不能把演练升级成真执行。
- 审批状态：pending → approved/rejected；approved 只能原子消费一次变为 consumed；
  超时变 expired，客户端取消变 cancelled。过期批准不能消费。
- 每个有效格式的 exec 请求先写审计；名单变更与审批决定均与审计同事务提交。
  命令下发与最终回执沿用现有 Command 表。

旧 `POST /api/commands` 的 `kind=exec` 已接入相同名单与审批，origin 固定 human，
默认 dry-run 保留；它仍是阻塞 HTTP 请求，另开审批界面批准后才返回。
结束进程与隔离/解除隔离继续走现有三道闸门。
等待回执超时意味着执行结果未知，不代表命令没有执行，不自动再次下发。
EXEC 在重连时不自动补发，避免原命令已执行但回执丢失造成重复执行；原有响应动作维持补发。
跨节点 EXEC 投递确认失败记录为 `unknown`，不能据此断言执行失败。
合法迟到回执仍可将 unknown 更新为终态；回执绑定已验证的 agent 流及其资产，
终态不能被重复回执或较晚的 sent 更新覆盖。此实现不宣称 exactly-once 保证。

## SQL 查询身份

`query` 参数为 `{sql}`；返回 columns、rows、truncated。每次只读事务，5 秒超时、
最多 200 行和 64 KiB 序列化结果（含列名和元数据）。大行在数据库端拦截后才传输，
超限显式截断，不把部分结果当作完整覆盖；零行或首行超限时 columns 可能为空。

配置 `PI_QUERY_DATABASE_URLS` 前，数据库管理员必须为**每个组建立独立登录角色**，
只给该组固定过滤条件视图的 SELECT 权限，不授予其他组视图、业务基表或特权角色成员身份。
视图的组过滤应由数据库定义固化，不能依赖可被 SQL 修改的 session setting。
平台拒绝 superuser、CREATEROLE、CREATEDB、REPLICATION、BYPASSRLS 或能直接 SELECT
业务基表（包括列级授权）的账号。组视图的过滤内容与授权范围仍由数据库管理员负责，运行时不自动创建角色或视图。
不得填写平台的 `DATABASE_URL`，也不要让不同组共用可读全部组的账号。

未配置时完全不注册 query，不回退到平台数据库账号。SQL 不能用于写入报告；报告走
`report({title,markdown})`，平台强制绑定当前组和会话。

## 预设任务

实现：`server/internal/schedule`（加载、同步、调度）、`agentchat/task.go`（任务会话）、
`api/tasks.go`、`api/reportrender.go`。任务定义在仓库 `tasks/*.yml`，与 `rules/` 同构管理：

```yaml
id: daily-host-inspection      # 必填，库中主键
name: 每日主机巡检
schedule: "0 2 * * *"          # 五段 cron，支持 @daily 与 CRON_TZ= 前缀
model: ""                      # 空用 PI_MODEL
targets: { group: "*" }        # "*" 每组各跑一次，或写组名
approval_timeout: 10m          # 名单外命令的审批等待，超时按拒绝
dry_run: false                 # 不写默认 true（演练）
prompt: |
  ……
```

- 未知字段、坏 cron、重复 id 的文件整份跳过并记日志；YAML 删除的任务标记 removed，保留历史。
- 调度器集群单活，每 `SCHEDULE_INTERVAL_SECONDS` 重载 YAML 并检查到期；从上次运行起算下一个触发点，
  停机或停用期间错过的周期只补跑一次。空组不跑；同组上一轮未结束则跳过本轮。
  接管时遗留的 running 记为失败，不重放。
- 任务会话 `kind=task`、`initiator=system`。**系统身份不是用户**：审批闸门对它不查用户与组内角色，
  但要求会话是本组任务会话，资产作用域、名单（按 AI 来源走白名单）、审批、`RESPONSE_ENABLED`
  与 dry-run 照常生效；审批人看到的发起人为 `system`。用户名 `system` 保留，不能创建。
- 截断、轮数耗尽或会话结束时没有提交报告，一律记为失败。失败与报告都经 `WEBHOOK_URL` 外发
  （报告附摘要与 HTML 链接，链接前缀取 `WEBHOOK_LINK_BASE`）；推送失败只记日志，不重试。

| 接口 | 权限 | 说明 |
|---|---|---|
| `GET /api/tasks` | viewer | 任务列表 |
| `PATCH /api/tasks/{id}` | admin | `{enabled?, customSchedule?}`；`customSchedule` 传空串恢复 YAML 周期 |
| `GET /api/tasks/{id}/runs` | viewer | 最近 100 次运行，按组裁剪 |
| `GET /api/agent-reports/{id}/html` | 组 viewer | goldmark 渲染，原始 HTML 与危险链接被丢弃，带 CSP |
| `GET /api/agent-reports/{id}/pdf` | 组 viewer | headless Chromium 打印，禁外网；找不到 Chromium 返回 503 |

## 验证与后续

- `server/pi-runtime`: `npm ci --ignore-scripts && npm test`。
- `server`: `go build ./...`、`go vet ./...`、`go test ./...`。
- 集成测试：`INTEGRATION_DATABASE_URL=测试库 go test -tags integration -p 1 ./...`。
  必须使用可清空的独立测试库。
- 第 5 步可按上述接口制作会话、审批和报告页面。
- 第 6 步见上文「预设任务」。前端对话页（主入口）提供审批与命令名单（组 admin）、
  报告列表（HTML 新标签页 / PDF 下载）与任务页（admin 启停、改周期，运行记录可跳转会话）。
- 本次验证使用 mock 模型与模拟 agent 通道，尚未进行真实模型/受管主机验收。

## 执行容量与异常恢复

每个 server 进程最多同时启动 4 个 Pi 子进程，另容纳 32 个等待请求；
PDF 最多同时渲染 2 份，另容纳 8 个等待请求。队列满时返回失败，取消请求会释放名额。
调度器最多同时运行 4 个组任务，其余目标在调度循环内等待，不为每个组提前启动 goroutine。
这些是单节点限制，多节点总容量随节点数增长。

会话入库保存固定执行期限 `run_expires_at`：总超时包含排队时间，并额外留 1 分钟清理宽限。
每分钟将超期且仍为 `running` 的会话和关联任务运行标记为失败，不重放任何命令；
其他节点尚未到期的会话不受影响。升级前没有期限的旧记录，等待本节点一个完整运行上限
及清理宽限后再恢复；升级时应使用一致的 `PI_TIMEOUT_SECONDS` 并完成所有节点替换。

报告独立 HTML 自带 CSP，只允许内联样式及 data 图片；HTTP 页面额外启用 sandbox。
PDF 的 Chromium 同时设置阻断代理（包括 loopback）与 DNS 规则，禁止报告里的 IP 或域名外链请求。
任务定义与运行记录均按组可见；没有任何组的普通用户看不到通配组任务定义。
