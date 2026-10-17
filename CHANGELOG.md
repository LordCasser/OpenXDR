# 变更记录

格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。
0.x 期间接口、配置与数据库结构仍可能不兼容变更，升级前请看对应条目。

## [0.1.0] - 未发布

第一个公开版本。

### 接入与纳管

- 控制台按组签发接入令牌，Linux / Windows 一行命令安装 agent，本机生成私钥、server 签发主机绑定证书。
- agent 经已认证的 gRPC 通道自动升级，校验哈希与自检后替换，保留上一版。
- 运维文档导入（YAML / JSON / Markdown 代码块与表格），凭据 AES-256-GCM 加密、按组授权 SSH 纳管。
- 按主机下发采集配置，坏配置退回内置默认。

### 采集

- agent：进程启停（eBPF → netlink → ETW → 轮询自动降级）、敏感文件（fanotify / inotify / ReadDirectoryChangesW）、
  持久化点快照、登录与安全日志、网络出站、内核模块加载。
- sensor：AF_PACKET v3 / AF_XDP 双后端，DNS、TLS（SNI / JA3 / JA3S / 证书）、HTTP 元数据。
- syslog 接入（UDP + TCP，RFC3164 / RFC5424）；入库前脱敏。

### 检测与降噪

- Sigma 兼容规则引擎，热重载，ATT&CK 覆盖矩阵；`validation/` 语料与 `detectcheck` 在 CI 守住检测能力。
- 威胁情报碰撞（IP / 域名 / 哈希），内置 abuse.ch 等公开订阅。
- 持久去重、可撤销且有有效期的误报抑制、按实体关联成事件图、UEBA 首次出现检测、爆破得手升级。
- AI 研判：带只读调查工具主动查证后定性。
- 事件结案与结案说明；需人工复核的口径（未判良性或高危及以上）；低危良性事件到期自动结案。

### AI 助手与巡检

- AI 助手对话：在组内主机执行命令、按组只读视图查库、登记运维待办、提交报告。
- 命令高风险名单：命中即阻塞等组管理员批准并通知，其余直接执行；人工与 AI 分别配置。
- 事件与待办可多选「交给 AI」，对象当前状态随每轮注入上下文。
- 对话在服务端后台运行，切页不打断，可随时停止。
- 预设任务按 cron 定时巡检，报告 HTML / PDF 渲染。

### 响应与通知

- 结束进程（校验进程 GUID 与创建时间）、隔离与解除隔离主机（Linux nftables / Windows WFP）。
- 全局开关与隔离放行清单两道闸门；自动响应需单独开启。
- Webhook 通知（generic / 钉钉 / 飞书 / 企业微信），主机失联与恢复通知。

### 平台

- 三档全局角色 + 组内角色，会话 cookie 认证，登录与处置审计。
- mTLS 与按主机绑定证书；NATS JetStream 按资产分片队列，多节点 server。
- 跨宿主机高可用部署（Patroni + 三节点 JetStream + Keepalived VIP）与滚动发布脚本。
- Web 控制台：中英双语，AI 助手为主入口，命令面板。

[0.1.0]: https://github.com/yaklang/OpenXDR/releases/tag/v0.1.0
