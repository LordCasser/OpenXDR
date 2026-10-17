# OpenXDR

[![CI](https://github.com/yaklang/OpenXDR/actions/workflows/ci.yml/badge.svg)](https://github.com/yaklang/OpenXDR/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

中文 | [English](README.en.md)

开源 XDR 平台：EDR + SIEM + 全流量分析，AI 驱动降噪与运维。

**纳管即运维，纳管即安全。** 主机装上 agent、划进组，就自动获得持续的采集、检测、
每日巡检与可对话的 AI 助手；人负责拍板，不再在告警列表里翻找。

**一万条告警进，三个真事件出。**

## 能做什么

- **一条命令接入主机**：控制台按组签发接入令牌，Linux / Windows 一行命令装好 agent，
  本机生成私钥、server 签发主机绑定证书；之后新版放进分发目录，在线 agent 自动升级，不用再登录主机。
  已有运维文档可直接导入，凭据加密保存并按组授权 SSH 纳管。
- **采集不挑环境**：进程、文件、持久化点、登录与安全日志、网络出站、内核模块；
  eBPF / ETW 可选，不可用时自动降级到 netlink、fanotify、轮询，宁可弱采集也不产假数据。
  全流量探针只出会话元数据（DNS / TLS JA3 与证书 / HTTP），不存 PCAP；另有 syslog 接入。
- **层层降噪**：Sigma 兼容规则（热重载、ATT&CK 矩阵标出「有规则无数据源」的缺口）、
  威胁情报碰撞（内置 abuse.ch 等公开订阅）、持久去重、可撤销的误报抑制、按实体关联成事件图、
  UEBA 首次出现检测，最后由 AI 带调查工具主动研判。低危良性事件到期自动结案，
  需要人复核的永远留给人。
- **AI 助手与巡检**：对话即运维——AI 可在组内主机上执行命令、按组只读视图查库、登记运维待办、
  提交报告。事件与待办可多选「交给 AI」接着处理。对话在服务端后台运行，切页不打断。
  预设任务按 cron 定时巡检全组主机，产出 HTML / PDF 报告。
- **人始终拍板**：命中高风险名单的命令阻塞等组管理员批准并通知，其余直接执行；
  结束进程 / 隔离主机受全局开关与隔离放行清单约束；所有登录、审批与处置落审计。
- **能上生产**：mTLS 与按主机绑定证书、三档 RBAC 与组权限、NATS JetStream 按资产分片队列、
  多节点 server，以及 Patroni + Keepalived 的跨宿主机高可用部署方案。

## 架构

```
┌─────────┐  ┌──────────┐  ┌──────────┐
│  Agent  │  │  Sensor  │  │  Syslog  │
│ 端点采集 │  │ 全流量探针│  │ 日志接入  │
└────┬────┘  └────┬─────┘  └────┬─────┘
     └────────────┼─────────────┘  gRPC (mTLS)，agent 主动连出
                  ▼
   ┌──────────────────────────────┐
   │ Server (Go)                  │
   │  归一化 → JetStream 分片队列  │
   │  规则 / 情报 / UEBA 检测      │
   │  去重 → 抑制 → 关联 → AI 研判 │
   │  AI 助手 · 定时巡检 · 命令审批 │──→ Webhook（钉钉 / 飞书 / 企微）
   └──────────────┬───────────────┘
                  ▼
   PostgreSQL ←→ Web 控制台（React）
```

详见 [架构文档](docs/architecture.md)。

## 快速开始

```bash
docker compose up -d
# 控制台 http://localhost:5173   API :8080   gRPC 接入 :8081
docker compose logs server | grep admin   # 首次启动生成的 admin 密码
```

接入模型（任意 OpenAI 兼容端点）后开启 AI 研判与 AI 助手：

```bash
AI_BASE_URL=http://<推理服务>/v1 AI_MODEL=<模型名> PI_MODEL=<模型名> docker compose up -d
```

然后在「资产 → 添加主机」复制安装命令到被监控主机上执行。接入主机需要 HTTPS 控制台与 mTLS，
完整步骤、采集方式、mTLS、情报、抑制、响应处置与全部配置项见 [部署与使用手册](docs/deployment.md)。

## 文档

| 文档 | 内容 |
|---|---|
| [部署与使用手册](docs/deployment.md) | 启动、接入主机、日志与情报、抑制与处置、mTLS、配置项全表 |
| [高可用部署](deploy/ha/README.md) | Patroni + 三节点 JetStream + Keepalived VIP，滚动发布 |
| [AI 助手与巡检](docs/pi-backend.md) | 会话、命令名单与审批、只读查询、运维待办、预设任务 |
| [文档导入与主机纳管](docs/host-enrollment.md) | 运维文档导入、凭据加密、SSH 纳管 |
| [架构](docs/architecture.md) · [采集端](docs/collection.md) · [事件模型](docs/events.md) · [检测链路](docs/detection.md) | 设计与实现细节 |
| [REST API](docs/api.md) · [集群与可观测性](docs/cluster.md) · [路线图](docs/roadmap.md) | 对接、运维与规划 |

完整索引见 [docs/README.md](docs/README.md)。

## 目录

| 目录 | 说明 |
|---|---|
| `agent/` | Rust 端点 agent（Linux / Windows），含响应处置 |
| `sensor/` | Rust 全流量探针，AF_PACKET v3 / AF_XDP 双后端 |
| `server/` | Go 后端：接入、检测、关联、AI 研判与助手、REST / gRPC |
| `web/` | React 管理控制台 |
| `rules/` | Sigma 兼容检测规则 |
| `tasks/` | 预设巡检任务（YAML） |
| `validation/` | [检测验证语料](validation/README.md)：真实攻击命令回放过规则引擎，CI 守住检测能力 |
| `deploy/` | 集群与高可用部署 |
| `proto/` | gRPC 契约 |

## 当前状态

v0.1.0 是第一个公开版本。Linux 采集、检测、AI 助手与巡检已在双节点高可用环境持续运行；
Windows 代码在 CI 中交叉编译检查，尚缺系统的实机验证。AI 效果依赖所接模型的
tool calling 能力，模型越弱越容易在长上下文里跑偏——平台保证它越不过权限与审批边界，
但不保证结论正确，事件仍由人结案。

已知缺口与后续计划见 [路线图](docs/roadmap.md)，变更记录见 [CHANGELOG](CHANGELOG.md)。

## 参与

欢迎 Issue 与 PR，提交前请读 [CONTRIBUTING.md](CONTRIBUTING.md)；安全问题请按
[SECURITY.md](SECURITY.md) 私下报告。

## 许可证

[Apache License 2.0](LICENSE)
