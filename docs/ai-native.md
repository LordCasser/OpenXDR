# AI 原生架构（设计稿）

> 状态：**设计定稿，未实现**。本文记录 2026-10-16 讨论确定的演进方向；
> 实现落地后各节改为以代码为准并标注源码位置。

核心理念：**纳管即安全**——主机装上 agent、划进组，就自动获得持续的运维与安全巡检，
人通过对话使用平台，而不是在告警列表里翻找。

## 一句话架构

每台主机的 agent 回传数据、执行平台下发的命令；平台托管 Pi Agent，按预设定时任务
（分钟 / 小时 / 天级）调用 agent 巡检并查询已存数据，产出报告、回写告警、Webhook 外发；
前端以 Agent 对话为主，专家模式查看 XDR 原有数据。

```
┌──────────────────── Web ────────────────────┐
│ Agent 对话页（主）     │ 专家模式（资产/事件/告警/incident/报告）│
└──────────────────────┬──────────────────────┘
                       │ REST + SSE
┌──────────────────────▼──────────────────────┐
│ 平台 server（Go）                             │
│  调度器：预设任务 YAML → 定时拉起 Pi 会话       │
│  Pi 托管：每会话一个子进程，RPC(JSONL) 驱动      │
│  工具 API：exec / query / report / notify      │
│  组 + RBAC、命令白名单、审批、审计             │
│  现有链路保留：接入 → sigma/intel → 告警/incident│
└───────┬──────────────────────────┬───────────┘
        │ RPC (stdin/stdout JSONL)  │ gRPC + mTLS（现有控制信道）
┌───────▼────────┐         ┌───────▼────────┐  ┌──────────┐
│ Pi 进程（原生） │         │ agent × N       │  │ sensor   │
│  xdr extension  │         │ 回传数据 + 执行命令│  │ 流量元数据 │
│  skills/        │         └────────────────┘  └──────────┘
└────────────────┘
```

## 组件职责

| 组件 | 职责 | 相对现状的变化 |
|---|---|---|
| agent | 回传数据（现有采集全保留）+ 执行平台命令 | 新增 `EXEC` 命令；整体保持轻量 |
| sensor | 流量会话元数据入库 | 不变，数据供 Pi 端网互证 |
| server | 接入存储、调度、托管 Pi、工具 API、组/RBAC/审批、报告、通知 | 新增组、任务、会话、报告、审批；现有检测链路保留 |
| Pi | 平台侧子进程，原生不改；通过 extension 获得工具、通过 skill 获得巡检知识 | 新增；取代 `triage` 的研判与狩猎职责 |
| web | Agent 对话页 + 专家模式 | 主入口改为对话页，现有页面并入专家模式 |

## Pi 集成

- **托管方式**：Go 平台以 RPC 模式启动 Pi 子进程，打进 server 同一镜像（镜像内带
  Node 运行时）。**每个会话一个进程**——每次对话、每次任务运行各自独立，结束即退出，
  崩溃只影响单个会话。
- **不改 Pi**：只用 Pi 原生扩展机制：
  - `extension`（TS，几十行）：注册下文四个工具，实现为调用平台本地 API；
    关闭 Pi 内置 read/write/edit/bash（原型阶段可保留，见"暂缓"）。
  - `skills/`：巡检方法、表结构说明、报告模板、端网互证方法等知识，随仓库维护。
- **会话身份**：拉起进程时注入短期 token，绑定发起人（定时任务为系统身份）与所属组；
  所有工具调用由平台 API 按 token 判权，Pi 侧不做任何权限判断。
- **会话历史**：平台消费 RPC 事件流（消息、工具调用、结果）入库，用于对话回放、
  专家模式查看与审计；不依赖 Pi 自带的 jsonl 会话文件。
- **多模型**：模型按任务配置（YAML 字段），对话使用组默认模型；Pi 本身支持多家
  provider，平台只负责把模型配置传给进程。
- **未验证**：extension 注册工具的接口、RPC 事件格式目前只读过第三方资料，
  实现前须对照 `badlogic/pi-mono` 仓库核实。

## 工具

| 工具 | 参数 | 语义 |
|---|---|---|
| `exec` | host, cmd, timeout | 经控制信道下发到 agent 执行；Linux `sh -c`、Windows PowerShell；一次性、带超时、输出截断，不支持交互 |
| `query` | sql | 只读数据库角色 + 视图；表结构写在 skill 里 |
| `report` | title, markdown | 提交报告；平台用 goldmark 转 HTML，headless Chromium 渲染 PDF |
| `notify` | channel, text | 走现有 `notify` 包（generic / dingtalk / feishu / wecom） |

另：Pi 研判出的结论回写为告警 / incident，打 `source=ai` 标记，专家模式可见
（通过 `report` 附带结构化段落或独立工具，实现时定）。

## 命令执行与审批

- agent 侧**无条件执行**收到的命令；所有控制在平台侧。
- 名单策略按组配置：**AI 发起的命令走白名单，人工发起的走黑名单**。
- 名单外命令进入审批队列，有审批权限的用户在前端批准 / 拒绝。
- `exec` **阻塞等待审批**（对话与定时任务一致）。定时任务设审批超时，
  **超时按拒绝处理**，Pi 继续执行并在报告中注明"某命令未获审批"。
- 每条命令（含被拒、超时）落审计日志。
- 现有结束进程 / 隔离主机命令及其三道闸门不受影响。

## 组与 RBAC

- **组**：几十台主机一组，支持多组，主机归属一个组。
- RBAC 在现有三档角色（admin / analyst / viewer）基础上**按组授权**：
  用户在每个组内有各自角色；admin 全局。
- 对话默认限定在组内；admin 可开跨组对话。
- 审批权限归入组内角色（具体哪档可批，实现时定）。

## 预设任务

仓库内 YAML，与 `rules/` 同构管理；UI 可启停、改周期。

```yaml
id: daily-host-inspection
name: 每日主机巡检
schedule: "0 2 * * *"
model: <provider/model>
targets: { group: "*" }        # 资产选择器
approval_timeout: 10m
prompt: |
  对组内每台主机做一次运维与安全巡检……按 skill「巡检报告」模板输出。
```

周期分层建议：分钟级做轻量确定性检查（异常才深挖）、小时级做近期数据研判、
天级做全面巡检与报告。

## 数据模型增量（`server/ent/schema/`）

| 实体 | 关键字段 |
|---|---|
| Group | name |
| GroupMember | user, group, role |
| Asset（改） | + group |
| Task | id, schedule, model, targets, prompt, enabled（YAML 同步） |
| TaskRun | task, started/finished, status, session |
| AgentSession | kind(chat/task), group, initiator, model, status |
| SessionMessage | session, seq, role, content / tool_call / tool_result |
| Report | session, group, title, markdown, created_at（HTML/PDF 按需渲染） |
| CommandPolicy | group, mode(allow/deny), origin(ai/human), pattern |
| Approval | session, host, cmd, status, decided_by, decided_at |

协议增量（`proto/agent.proto`）：`CommandKind` 加 `EXEC`；`Command` 加
`cmd`、`timeout_ms`；`CommandResult` 加 `exit_code`、`stdout`、`stderr`、`truncated`。

## 与现有链路的关系

- **保留**：agent/sensor/syslog 接入、sigma 与情报检测、告警 / incident、去重抑制、
  响应处置、通知、审计、集群。实时信号照常持久化，Pi 通过 `query` 查询。
- **取代**：`triage`（AI 研判 + 对话式狩猎）由 Pi 会话承担；落地后再决定删除时机。
- **前端**：现有页面整体进入专家模式。

## 被推翻的现有原则

以下条目在实现落地时同步修改：

| 位置 | 现有原则 | 新做法 |
|---|---|---|
| `AGENTS.md:126`、`docs/architecture.md:106`、`docs/detection.md:227` | 刻意不做 NL2SQL | `query` 工具开放只读 SQL |
| `AGENTS.md:126`、`docs/detection.md:209` | LLM 只能调用参数空间受限的调查工具 | `exec` 下发任意命令，由平台名单与审批约束 |
| `AGENTS.md:126` | 研判最多 6 轮 | 轮数由 Pi 会话控制，平台侧改为超时 / 预算约束 |
| `AGENTS.md:103` | `triage` 负责研判与狩猎 | 由 Pi 会话承担 |

## 暂缓（原型后补足安全）

原型阶段明确不做，后续补：

- 提示注入防护：会话资产作用域（会话只能对绑定资产执行）、工具结果隔离标记
- 名单匹配升级为命令 AST 解析（`mvdan.cc/sh`），拒绝 `eval` / 命令替换等不可静态判定结构
- agent 本地硬禁止策略（远程不可改）
- 关闭 Pi 内置 bash 等工具
- 单会话 token / 费用预算

## 里程碑 M1

目标：**装上 agent → 能对话 → 收到报告**。

1. 协议与 agent：`EXEC` 命令执行（超时、截断、Linux / Windows）
2. server：组 + 资产归组 + 按组 RBAC
3. server：Pi 托管（子进程、RPC、事件入库）+ `xdr` extension + 工具 API（`exec` / `query` / `report`）
4. server：命令白名单 / 黑名单 + 阻塞审批
5. web：Agent 对话页（工具调用渲染为卡片）+ 审批入口
6. 调度器 + 一个天级巡检任务 + 报告 Markdown / HTML / PDF + Webhook 外发
