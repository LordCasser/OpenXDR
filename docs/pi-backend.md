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

Pi 不注册内置文件和 shell 工具，平台只暴露 exec/track/report，以及已配置组的 query。
没有新增对外工具执行端口，身份、组和来源均由 Go 绑定，模型不能修改；命令一律真执行，没有演练模式。
每轮上下文包含本组最多 200 台资产的 UUID、主机名和 OS；超出会标注截断。
每轮最多「组内主机数 × 20 + 遗留待办数 + 32」次模型调用（32–256），预算写进系统提示让模型留出提交报告的余量，每次输出最多 8192 token。exec 送入模型的 stdout/stderr 各最多 16 KiB，截断标记为 `truncated=true`，Command 记录仍保留原始回执。GLM 显式关闭模板 thinking。未实现费用预算或自动历史压缩。

## 前端接口

所有请求使用现有会话 cookie 与同源保护。请求字段采用下表的 camelCase；直接返回的
Ent 实体字段采用 snake_case（例如 `group_id`、`created_at`）。

| 接口 | 请求 | 权限与响应 |
|---|---|---|
| `POST /api/agent-sessions` | `{groupId,title?,subjects?}` | 组 analyst；创建 idle 会话，返回 201 + 实体。`subjects` 是「交给 AI」绑定的对象，`incident:<id>` 或 `finding:<id>`，最多 10 个且必须都属于该组；绑定后每轮把这些对象的当前状态（事件含研判与最要紧的 10 条告警及证据）放进系统提示，事件仍由人结案，AI 只给结案建议 |
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
轮数耗尽（`max_turns`）时服务端先在同一会话上带全部历史续一次收尾（最多 4 次调用）：
两种会话都只留 `report`：对话会话要求直接用文字总结、不再调用工具，任务会话要求提交报告；未覆盖的检查项标「未验证」。
不能一个工具都不给：历史里有工具调用时 pi-ai 会发空的 `tools` 数组，vLLM 等端点直接 400。收尾消息照常入库。
客户端断开会终止推理与审批等待，已下发的命令不会因此撤销。
同一会话只允许一个 running 请求；失败会话不自动重试，需检查命令记录后另建会话。
进程异常退出导致遗留 running 状态时，不自动恢复或重放主机操作。

## exec 与审批

`exec` 参数：`{host:资产UUID,cmd:完整命令,timeout?:秒}`，timeout 为 1–300，默认 agent 的 60 秒。
执行只允许当前组资产；等待审批后会再次检查成员角色和资产归组。

- 名单一律是高风险名单（mode `deny`），AI 与人工各一份：命令命中本组该来源任一条目就挂起、
  等组 admin 审批，其余直接执行。空名单意味着没有额外审批。创建名单时 mode 固定为 `deny`，
  请求体仍是 `{groupId,origin,pattern}`。
- pattern 为 Go 正则，在整条命令里**非锚定搜索**：`\brm\s` 也命中 `x && rm -rf /`、`/bin/rm -rf`。
  需要只匹配开头或整条时自己写 `^`、`$`。创建时校验能否编译。
  **这不是 shell AST 解析**，变量、别名、编码等写法可以绕开，名单只是拦住常见的高风险操作。
- 新建的组自带一套 AI 高风险名单（`commandgate.DefaultAIDeny`，Linux 与 Windows 各一套）：
  递归/强制删除、格式化与分区、`dd of=`、关机重启、停用服务、结束进程、防火墙改动、账户变更、
  卸载软件包、zfs/zpool destroy|rollback、Proxmox 停机销毁与集群变更、`crontab -r`、
  下载脚本直接交给 shell、重定向或 `tee` 写入 `/etc` `/boot` `/usr` `/bin` `/sbin` `/lib`、
  读取 `/etc/shadow` 与 SSH 私钥；Windows 侧覆盖关机重启、递归删除、格式化磁盘、停止/禁用服务、
  禁用网卡、本地账户与管理员组变更、Defender 设置、结束进程与防火墙改动。只读巡检命令不受影响。
  删组时名单一并清掉。
- **名单不交给模型。** 系统提示只告诉模型：命令直接执行，少数高风险操作会暂停等组管理员批准、
  管理员已收到通知，这不是拒绝，不要改写或拆分命令绕开，先做不依赖它的工作，最后列出待批准的操作。
  等待超时返回给模型的同样是「仍在等待批准（已通知），暂未执行」；管理员明确驳回时才告诉它
  没被批准、不要换写法重复。
- 每条审批创建时经通知配置外发一次（标题「待批准：AI 请求执行高风险命令」或人工对应标题，
  正文含组、主机、发起人和截断到 300 字的命令，链接 `/approvals`）；发送失败只记日志。
- 升级时启动迁移：删掉全部旧版 AI 免审批（ai/allow）条目，只给这次删到条目的组补一份默认高风险名单。
  再次启动没有 allow 条目可删，管理员主动清空的名单不会被补回。
- 名单之外照样受组权限与 `RESPONSE_ENABLED` 约束。审批只批准原始资产、命令与超时的组合，
  批准后按原样真执行。
- 审批状态：pending → approved/rejected；approved 只能原子消费一次变为 consumed；
  超时变 expired，客户端取消变 cancelled。过期批准不能消费。
- 每个有效格式的 exec 请求先写审计；名单变更与审批决定均与审计同事务提交。
  命令下发与最终回执沿用现有 Command 表。

旧 `POST /api/commands` 的 `kind=exec` 已接入相同名单与审批，origin 固定 human，
同样真执行；它仍是阻塞 HTTP 请求，另开审批界面批准后才返回。
结束进程与隔离/解除隔离继续走 `RESPONSE_ENABLED` 与 `ISOLATION_ALLOW` 闸门。
等待回执超时意味着执行结果未知，不代表命令没有执行，不自动再次下发。
EXEC 在重连时不自动补发，避免原命令已执行但回执丢失造成重复执行；原有响应动作维持补发。
跨节点 EXEC 投递确认失败记录为 `unknown`，不能据此断言执行失败。
合法迟到回执仍可将 unknown 更新为终态；回执绑定已验证的 agent 流及其资产，
终态不能被重复回执或较晚的 sent 更新覆盖。此实现不宣称 exactly-once 保证。

## SQL 查询身份

`query` 参数为 `{sql}`；返回 columns、rows、truncated。每次只读事务，5 秒超时、
最多 200 行和 8 KiB 序列化结果（含列名和元数据）。大行在数据库端拦截后才传输，
超限显式截断，不把部分结果当作完整覆盖；零行或首行超限时 columns 可能为空。
SQL 出错时把 PostgreSQL 报错原文（只取 message）返回给模型，便于它自行改正。
视图只有 rule_id，规则名由平台在系统提示数据的 `rule_titles` 里给出（本组近 7 天命中过的规则）。

每个组使用**独立登录角色**，只能 SELECT 该组固定过滤条件的视图，读不到其他组视图、业务基表，
也没有特权角色成员身份。视图的组过滤由数据库定义固化，不依赖可被 SQL 修改的 session setting。
平台拒绝 superuser、CREATEROLE、CREATEDB、REPLICATION、BYPASSRLS 或能直接 SELECT
业务基表（包括列级授权）的账号。

**自动开通**（`server/internal/queryrole`）：平台数据库账号有 CREATEROLE（或是超级用户）时，
建组即为该组建 schema `xdr_g_<组 UUID 末 12 位>` 与角色 `<schema>_ro`，随机密码存在组记录上
（不经任何接口返回）；server 启动时给所有组补齐并刷新视图定义，删组时回收 schema 与角色。
开通用事务级 advisory lock 串行化，集群多节点并发安全。HA 部署在 patroni 初始化时已给 openxdr
账号 CREATEROLE；已有集群执行一次 `ALTER ROLE openxdr CREATEROLE`。

**手工开通**：平台账号没有 CREATEROLE 时（启动日志会提示），用 `deploy/pi-query/group-views.sql`
（psql 变量传组 UUID、schema、角色与密码，可重复执行）建视图与角色，再写进
`PI_QUERY_DATABASE_URLS`（JSON：组 UUID → DSN）。手工配置的身份始终优先于自动开通。
两种方式建的都是 assets / events / alerts / incidents / commands 五个按组固化过滤的视图，
incident 与 REST 同口径（全部告警都在本组才可见），角色只读、5 秒超时、最多 5 个连接。
不得填写平台的 `DATABASE_URL`，也不要让不同组共用可读全部组的账号。

组未开通时完全不注册 query，不回退到平台数据库账号。SQL 不能用于写入报告；报告走
`report({title,markdown})`，平台强制绑定当前组和会话。

## 运维待办

`track({host,key,title,detail?,severity,status})` 按（组、主机、key）登记或复查一条待办，
`status=open` 新登记或确认仍在（之前标过修复的会重开），`status=resolved` 表示复查确认已修复，
`status=withdrawn` 撤回本轮新登记的条目（直接删除，遗留待办不能撤回）。只收需要人处理的问题：
severity 只有 low / medium / high，detail 必填，每轮最多新登记 10 条。
主机必须属于本组；没有对应待办时不能标修复。人工 `ignored` 的待办 track 原样返回忽略原因、不做改动。
每轮会话的系统提示数据带 `open_findings`（遗留）与 `ignored_findings`（忽略及原因，各最多 100 条），
模型据此先复查遗留、不再报忽略项；轮数预算按遗留条数加宽。人在控制台「运维待办」标已处理或忽略，
接口见 `docs/api.md`。删组、主机换组或移出组时，该主机在原组的待办一并删除。

## 预设任务

实现：`server/internal/schedule`（加载、同步、调度）、`agentchat/task.go`（任务会话）、
`api/tasks.go`、`api/reportrender.go`。任务定义在仓库 `tasks/*.yml`，与 `rules/` 同构管理：

```yaml
id: daily-host-inspection      # 必填，库中主键
name: 每日主机巡检
schedule: "0 2 * * *"          # 五段 cron，支持 @daily 与 CRON_TZ= 前缀
model: ""                      # 空用 PI_MODEL
targets: { group: "*" }        # "*" 每组各跑一次，或写组名
approval_timeout: 10m          # 高风险命令的审批等待，到期不执行
prompt: |
  ……
```

- 未知字段、坏 cron、重复 id 的文件整份跳过并记日志；YAML 删除的任务标记 removed，保留历史。
- 调度器集群单活，每 `SCHEDULE_INTERVAL_SECONDS` 重载 YAML 并检查到期；从上次运行起算下一个触发点，
  停机或停用期间错过的周期只补跑一次。空组不跑；同组上一轮未结束则跳过本轮。
  接管时遗留的 running 记为失败，不重放。
- 任务会话 `kind=task`、`initiator=system`。**系统身份不是用户**：审批闸门对它不查用户与组内角色，
  但要求会话是本组任务会话，资产作用域、名单（按 AI 来源的高风险名单）、审批与
  `RESPONSE_ENABLED` 照常生效，命令真执行；审批人看到的发起人为 `system`。用户名 `system` 保留，不能创建。
- 截断、收尾后仍轮数耗尽或会话结束时没有提交报告，一律记为失败。失败后立即换一个新会话重跑一次
  （同一行运行记录改挂新会话，失败那次的会话与错误留在会话历史里）；超时或失去租约不重跑。
  重跑仍失败才算这一轮失败。失败与报告都经通知配置外发
  （报告附摘要与 HTML 链接，链接前缀取通知配置里的控制台地址）；推送失败只记日志，不重试。

| 接口 | 权限 | 说明 |
|---|---|---|
| `GET /api/tasks` | viewer | 任务列表 |
| `PATCH /api/tasks/{id}` | admin | `{enabled?, customSchedule?}`；`customSchedule` 传空串恢复 YAML 周期 |
| `POST /api/tasks/{id}/run` | admin | 立即运行：记下请求时间，调度器下一次检查时对每个目标组各跑一轮；停用的任务返回 409 |
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

调度按 `(task_id, group_id)` 分别计算到期时间，从任务持久创建时间起算；
运行记录保存 `scheduled_at`，同任务、同组、同触发时刻有数据库唯一约束。
只启动部分组后发生重启，尚未启动的组会补跑一次，不重放已启动组的命令。
Windows 隔离的 WFP 权重设计依据 [Microsoft Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)：
许可和默认阻断置于同一独立子层；不覆盖其他产品或系统策略的阻断。
