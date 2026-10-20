# OpenXDR

[![CI](https://github.com/yaklang/OpenXDR/actions/workflows/ci.yml/badge.svg)](https://github.com/yaklang/OpenXDR/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

中文 | [English](README.en.md)

开源 XDR 平台：EDR + SIEM + 全流量分析，AI 驱动降噪与运维。

**纳管即运维，纳管即安全。** 主机装上 agent、划进组，就自动获得持续的采集、检测、
每日巡检与可对话的 AI 助手；人负责拍板，不再在告警列表里翻找。

**噪音止步于此，留下的都值得一看。**

## 能做什么

- **一条命令接入主机**：控制台按组签发接入令牌，Linux（x86_64 / arm64）/ Windows 一行命令装好 agent，
  本机生成私钥、server 签发主机绑定证书；之后新版放进分发目录，在线 agent 自动升级，不用再登录主机。
  已有运维文档可直接导入，凭据加密保存并按组授权 SSH 纳管。
- **采集不挑环境**：进程、文件、持久化点、登录与安全日志、网络出站、内核模块；
  eBPF / ETW 可选，不可用时自动降级到 netlink、fanotify、轮询，宁可弱采集也不产假数据。
  全流量探针只出会话元数据（DNS / TLS JA3 与证书 / HTTP），不存 PCAP；另有 syslog 接入。
- **层层降噪**：Sigma 兼容规则（热重载、ATT&CK 矩阵标出「有规则无数据源」的缺口）、
  威胁情报碰撞（内置 abuse.ch 等公开订阅）、持久去重、可撤销的误报抑制、按实体关联成事件图、
  UEBA 首次出现检测，最后由 AI 带调查工具主动研判。低危良性事件到期自动结案，
  需要人复核的永远留给人。另有时序检测（计数与序列规则，独立目录，显式开启，开发中）。
- **软件漏洞**：agent 上报 dpkg 软件清单，server 按 OSV 漏洞库比对，标出可升级修复的漏洞与
  受影响的对外服务；支持离线漏洞库。目前只覆盖 Debian / Ubuntu。
- **身份关联**（开发中）：归一化 Linux / Windows 登录与本地账号，可从 Keycloak、Entra ID、AD / LDAP
  同步目录账号；未核实目录权威前不跨设备合并同名账号。
- **资产图谱与攻击面**：agent 上报监听端口与云环境，连接关系聚合成依赖图；AI 标注每台资产的
  角色、功能与重要程度（人工可改可锁）。资产按网段、云环境、IP 自动划成内网 / 隔离区 / 公网区 / 云上，
  每个对外服务按暴露级别 × 端口风险 × 重要程度排序，连过却没纳管的机器列为盲区。
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

## 安装

一台装了 Docker 的 Linux 服务器，一行命令：

```bash
curl -fsSL https://github.com/yaklang/OpenXDR/releases/latest/download/install.sh | sudo sh -s -- <控制台域名或 IP>
```

脚本生成口令与密钥、签发 mTLS 证书、配好 HTTPS（解析到公网的域名自动申请 Let's Encrypt，内网地址用自建 CA），
拉起后打印控制台地址与 admin 口令。登录后在「系统设置 → AI 模型」接上任意 OpenAI 兼容端点，
再到「资产 → 添加主机」复制安装命令到被监控主机上执行即可。再执行一遍就是升级。

**或者交给你的 AI agent**（Claude Code、Codex、Cursor 等，在目标服务器上运行），把这句话发给它：

```text
请在这台服务器上安装 OpenXDR，严格按照 https://github.com/yaklang/OpenXDR/blob/master/docs/install.md 操作：
先检查环境并问我控制台用哪个域名或 IP，再执行安装，最后把控制台地址、admin 口令，以及被纳管主机信任 CA 的命令告诉我。
```

详细步骤、核对、升级备份与常见问题见 [安装](docs/install.md)。从源码构建开发：

```bash
docker compose up -d
# 控制台 http://localhost:5173   API :8080   gRPC 接入 :8081
docker compose logs server | grep admin   # 首次启动生成的 admin 密码
```

## 文档

| 文档 | 内容 |
|---|---|
| [安装](docs/install.md) | 一行安装、核对、升级备份、常见问题，也是给 AI agent 的安装说明 |
| [部署与使用手册](docs/deployment.md) | 启动、接入主机、日志与情报、抑制与处置、mTLS、配置项全表 |
| [高可用部署](deploy/ha/README.md) | Patroni + 三节点 JetStream + Keepalived VIP，滚动发布 |
| [资产图谱与攻击面](docs/asset-map.md) | 设备清单、依赖边、区域划分、风险分与 AI 标注 |
| [AI 助手与巡检](docs/pi-backend.md) | 会话、命令名单与审批、只读查询、运维待办、预设任务 |
| [文档导入与主机纳管](docs/host-enrollment.md) | 运维文档导入、凭据加密、SSH 纳管 |
| [软件漏洞](docs/vulns.md) | dpkg 软件清单、OSV 漏洞库同步、版本比较、已知限制 |
| [时序检测](docs/temporal-detection.md) · [身份关联](docs/identity-correlation.md) | 计数与序列规则；登录归一化与目录同步（均开发中） |
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
| `temporal-rules/` | 时序检测规则（计数 / 序列），与 Sigma 规则分开存放 |
| `tasks/` | 预设巡检任务（YAML） |
| `validation/` | [检测验证语料](validation/README.md)：真实攻击命令回放过规则引擎，CI 守住检测能力 |
| `deploy/` | 集群与高可用部署 |
| `proto/` | gRPC 契约 |
| `schema/` | 设计参考 DDL，实际表结构以 `server/ent/schema/` 为准 |
| `pages/` | 项目主页（GitHub Pages），与产品代码无关 |

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

第三方数据：`rules/sigmahq/` 为 SigmaHQ 社区规则（DRL 1.1，见其 README）；发版镜像自带的离线 IP 归属库为
[DB-IP Lite](https://db-ip.com)（IP Geolocation by DB-IP，CC BY 4.0），见 [资产图谱](docs/asset-map.md#离线归属库)。
