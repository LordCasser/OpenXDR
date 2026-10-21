# Suricata EVE 告警接入

OpenXDR 接收 Suricata 已产生的 `alert`，复用持久队列、抑制、去重、关联与 AI 研判。
Suricata 独立执行 `.rules`；平台不执行该规则格式，不管理它的规则更新，不替换现有 sensor。
本接入不根据单条签名直接下发阻断。现有人工处置与 AI 自动响应仍受原有开关、授权和审计约束。

## 配置

接入走[外部系统集成 API](deployment.md#外部系统集成-api)，先确保 server 已设置 `INTEGRATION_API_ENABLED=true`
与 `INTEGRATION_CURSOR_KEY`。然后在控制台「系统集成」为每个探针建一个集成：

- scopes 选「Suricata 告警写入」（`suricata:write`），授权组**恰好一个**，即告警归属的组；
- 签发只带 `suricata:write` 的 Token，明文只显示一次，不要提交到 Git。

Token 只能写这个组的告警，不授予查询、执行或处置权限；吊销、到期、停用集成即刻生效，
轮换按签发新 Token、切换探针、吊销旧 Token 进行。改授权组只影响之后的投递，不会重写已入队证据。
探针身份取集成 ID（写入 `metadata.observer`），改集成名称不影响去重与幂等。

端点为 `POST /api/integration/v1/suricata/events`，使用 `Authorization: Bearer <Token>`，
不使用控制台 cookie。经已有 `/api/` 反向代理访问，远程传输必须使用 HTTPS。
告警写入是持续数据流，不受集成 API 面向人工调用的限流约束，由队列背压（503）与报文上限约束。

每次发送**一个完整 JSON 对象**，上限 256 KiB；不支持 JSON 数组或整个 JSONL 文件一次提交。
只接受 `event_type=alert`；DNS、HTTP、flow 等独立事件不导入，避免重复现有 sensor 的数据。

| HTTP 状态 | 意义与处理 |
|---|---|
| 202 | 队列已确认接收；异步模式不表示告警已落库或已完成研判 |
| 400 | 事件无效或当前不支持的事件类型/字段值；修正数据，不要盲目重试 |
| 401 | Token 无效、已吊销、已过期或集成已停用 |
| 403 | Token 或集成缺 `suricata:write`，或授权组不是恰好一个 |
| 405 | 方法不是 POST |
| 413 | 请求超过大小限制或读取失败 |
| 503 | 集成 API 未启用、队列/数据库失败等；保留原始事件，恢复后重传 |

连接超时可能已经接收。重传原始事件即可，服务端以来源组、集成 ID 和规范 JSON 生成稳定 ID；
重排 JSON 键或改变空白不产生新事件。重传不会增加告警计数；同一签名在同一地址对上的真实重复命中
（不论源端口）会在去重窗口内累计到一条告警。
不同集成（探针）独立去重，不声称已经解决多个探针重复观察同一报文的问题。

## 导入与转发

仓库提供一次性导入工具，不启动常驻进程。从 `server/` 构建：

```bash
go build -o /tmp/suricata-import ./cmd/suricata-import
export SURICATA_URL=https://xdr.example.com/api/integration/v1/suricata/events
read -rs SURICATA_TOKEN
export SURICATA_TOKEN
/tmp/suricata-import /var/log/suricata/eve.json
```

工具逐行读取，只发送 alert。无效行与服务端 400 跳过并在结束时报告行号（退出码 2），重试也不会成功；
网络错误和其他状态码立即停止（退出码 1），恢复后可从头重跑，已经接收的记录不会重复建告警。`-` 代表标准输入。工具不绕过 TLS 证书验证，不跟随重定向。
这不是持续文件采集器：生产持续转发应由已有采集器负责文件游标、轮转、磁盘缓冲与重试，
按上述单 JSON 协议发送；不要用没有持久游标的 `tail | curl` 宣称可靠采集。

## 字段与归属

- `source=suricata`、`class_uid=2004`；`src_endpoint`、`dst_endpoint` 和 `conn_tuple` 供检索与关联。
- `raw.suricata` 保留完整 EVE JSON 内容（规范化键顺序与空白，不承诺字节级原样）。`flow_id` 用精确 JSON 数值保存，
  `community_id`、规则 metadata、action、HTTP/TLS 上下文等未知字段也保留。
- 平台规则 ID 为 `suricata:<gid>:<signature_id>`；`rev` 保留在证据和告警依据里。
  严重度 `1/2/3/4` 映射为平台 `4/3/2/1`；不因单条签名直接标为 critical。
- 接受带时区的 RFC3339 时间以及 EVE 常见的 `+0800` 时区。协议名小写照录（`IPv6-ICMP` 规范为 `icmpv6`）；
  严重度接受 1..255，4 及以上都映射为平台最低级。
- 可信来源来自集成本身（集成 ID 与唯一授权组），写入 `metadata.observer/group_id`。EVE 内的同名字段、`asset_id`、
  进程 GUID 或平台指令标记都只是外部证据，不能覆盖平台身份。
- 消费时只在来源组内查当前资产 IP；事件须距**接收时刻**不超过五分钟（平台自身的队列积压不算迟到），
  资产 `first_seen` 不晚于事件、`last_seen` 不早于事件前五分钟。当前资产清单不是历史 IP 租约，
  探针迟到、时钟偏差超过五分钟或历史导入都保留未知归属。
- IP 统一成规范写法（IPv6 压缩、IPv4 映射地址还原）再匹配资产；`raw.suricata` 仍保留原文。
- 规则带 `alert.target.ip` 时仅匹配该端；否则每端各自在组内唯一匹配一台资产即归属。
  两端都是组内资产（东西向）时拆成两份证据、各出一条告警（目的端证据用派生的稳定 ID，重传仍幂等），
  再经横向关联归入同一 incident。重复 IP、无匹配的那一端保留未知，不把探针本身当作受影响资产。
  归属表示参与连接，不凭这个字段断言该主机已经被攻陷。
- 已归属告警按现有组权限展示；未知资产事件/告警沿用现有权限，**仅全局管理员可见**。
  未知告警按组、探针和发起端地址（规则标出的 `alert.source`，否则为连接源端）关联，
  同一来源扫描多台主机、多个端口归一个 incident；不进入跨来源的统一 unknown 桶。
  横向移动关联仅寻找同组资产，不能把另一组的同地址证据并进来。

告警原始证据可包含敏感网络内容；Suricata 侧按需要控制 payload 输出。本接口不会把负载转成可执行工具指令。

## 验证

```bash
go test ./internal/suricata ./cmd/suricata-import
INTEGRATION_DATABASE_URL='<专用测试库DSN>' go test -tags integration -p 1 \
  ./internal/ingest ./internal/correlate ./internal/api ./internal/triage -run Suricata -count=1
```

覆盖时间格式、数值精度、协议与严重度兼容、入口鉴权、大小限制、失败不确认、重传幂等、跨端口去重、
抑制及撤销、组内匹配、IP 规范化、东西向两端归属并关联成同一 incident、重复 IP、迟到事件、队列积压不丢归属、排队期间转组、未知归属隔离，以及 HTTP → PostgreSQL →
端点与网络告警关联成同一 incident、组权限展示，以及模拟模型接收证据并保存研判结果。
集成测试会清空指定测试库，不能指向生产库。
这些测试不替代真实 Suricata 抓包、生产转发器轮转/断网和真实模型研判验收。

格式依据：[Suricata EVE JSON Format](https://docs.suricata.io/en/suricata-8.0.6/output/eve/eve-json-format.html)。
