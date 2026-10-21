# OpenXDR 资产导出与系统联动设计

状态：通用能力已实现并完成本地验证，未提交、未部署、未连接厂商生产工单系统。设计基线为 2026-10-21 工作区 `6b3baa0`；阶段 A/B/C 的实现与验证范围见文末。下文“现有能力”描述设计基线，其余章节描述本次交付契约。

目标是让运营人员导出资产台账，让外部系统使用独立身份读取数据，并让安全事件进入工单、处理结果回到 OpenXDR。按三个可独立交付的阶段实施，不增加新的消息中间件，不要求部署特定厂商的工单系统。

## 1 当前实现与设计约束

| 现有能力 | 源码依据 | 对设计的影响 |
|---|---|---|
| 资产列表按可见组裁剪，前端本地搜索和筛选 | `server/internal/api/api.go:418`；`web/src/pages/AssetsPage.tsx:21` | 导出必须在服务端重新筛选和授权，不能信任前端传来的列表 |
| cookie 会话绑定 `ent.User`，按 HTTP 路径与方法授权 | `server/internal/auth/auth.go:132` | 不把 Bearer Token 直接接到全部管理接口 |
| incident 全部告警均在可见资产内才可见 | `server/internal/api/scope.go:88` | 不用列表中的单个 `groupId` 判断跨组事件权限 |
| incident 有单个 `notified_at` 标记 | `server/ent/schema/incident.go:29` | 不能承载多个订阅目标各自的重试进度 |
| 人工单条、批量结案，AI 研判和自动结案分别修改事件 | `server/internal/api/api.go:337`；`server/internal/api/incidentbatch.go`；`server/internal/triage/engine.go:178`；`server/internal/janitor/autoclose.go:41` | 新事件流必须覆盖全部变更入口 |
| IM 和 generic Webhook 共用一个目标 | `server/internal/notify/settings.go:14`；`server/main.go:372` | 现有通知保留，新机器订阅单独管理 |
| 有事务内强审计写入方法 | `server/internal/audit/audit.go:45` | 对接写操作、状态变更和审计放在同一事务 |

现有 Markdown incident 报告及 HTML/PDF 巡检报告继续使用。PDF 依赖可用的 Chromium，不能把代码存在视为所有部署均可下载。

## 2 交付范围

| 阶段 | 运营结果 | 包含 | 暂不包含 |
|---|---|---|---|
| A 资产导出 | 当前筛选或勾选的资产可以带走 | CSV、JSON、服务端权限与审计、导出范围说明 | 凭据导出、完整配置备份、原始日志大批量导出 |
| B 集成 API | CMDB 等系统不用人的密码登录 | 集成身份、Token、资产和事件只读接口、OpenAPI 契约 | OAuth 平台、通用数据库查询、资产双向自动覆盖 |
| C 事件工单联动 | 事件推送、工单关联、结果回写 | 多目标订阅、可靠投递、失败重放、外部工单关联、受控状态回写 | 可视化工作流编排、任意脚本、自动执行主机命令、厂商内置连接器大全 |

第一条完整联动路径为：OpenXDR 发出事件 → 外部适配器持久接收并去重 → 创建工单 → 回写工单编号 → 工单处理后回写结果。适配器负责厂商认证与字段映射；平台提供固定、可测试的通用契约。

## 3 资产导出

### 3.1 页面流程

资产页增加「导出」按钮。弹窗选择 CSV / JSON，并明确选择「当前筛选结果」或「已勾选资产」。后者没有勾选时不可选；前者表示全部匹配资产，不只是当前表格页。显示筛选摘要，最终数量以服务端结果为准。

导出权限沿用资产读取权限，viewer 可导出自己可见资产。按钮无需 admin 权限。所有资产 ID 在服务端重新授权；勾选集合混入无权或已删除资产时整次失败，不静默漏行。未分组资产仍仅全局 admin 可导出。

### 3.2 接口与格式

`POST /api/assets/export` 使用现有 cookie 认证；在认证路径表中显式允许 viewer，handler 仍做组授权。

```json
{
  "format": "csv",
  "selection": {"mode": "filter", "q": "web", "groupId": "UUID"}
}
```

勾选模式为 `{"mode":"ids","ids":["UUID"]}`。两种模式互斥，禁止混合；空组筛选表示全部可见组，`ungrouped` 表示未分组。搜索保持现有主机名不区分大小写、IP 子串的语义。字段名未知、格式无效、重复或超限选择须明确处理：ID 去重后计算数量，其他无效参数返回 400。

固定字段白名单：`id, hostname, os, osDisplay, ipAddrs, groupId, groupName, agentId, agentVersion, sensorVersion, firstSeen, lastSeen, sensorSeen, hostState`。不直接序列化 Ent 对象；不包含密码、私钥、凭据令牌、连接配置和原始健康 JSON。`hostState` 复用界面的状态规则，并以 `exportedAt` 为计算时点；不能仅用 `lastSeen` 将导入但未纳管资产判在线。

CSV 使用 UTF-8 BOM、固定英文表头与 CRLF，文本字段正确转义，多 IP 用分号连接。对以公式触发字符开头及前置空白后触发的文本进行表格公式防护；因此 CSV 是运营展示格式，不保证文本逐字往返。JSON 保留原值、数组和 null，供机器使用。

JSON 包装为 `{schemaVersion:"1", exportedAt, filters, count, items}`。CSV 响应头提供 `X-Exported-At` 与 `X-Export-Count`。时间为 RFC3339 UTC；中文字段说明放在文档中。文件名由服务端生成，例如 `openxdr-assets-20261021T080000Z.csv`，禁止用户输入进入响应头。

### 3.3 完整性与资源边界

首期同步导出最多 10,000 条、生成结果最多 32 MiB；均为待压测的初始保护值。一次只读一致性事务查询最多上限加一条，并读取对应组名；在受限缓冲区完成编码后才返回附件。超过任一上限返回 422 和缩小筛选的提示，不截断成看似完整的文件。请求超时初值 30 秒；数据库或编码失败时不发附件头。

授权以请求事务内检查结果为准；已开始响应的数据无法撤回。导出审计记录操作者、格式、过滤摘要、条数、请求 ID 和结果，不记录文件正文。审计成功后才开始响应；审计表示已生成并开始交付，不声称浏览器已保存。连接中断单独计为传输失败。

响应使用 `Cache-Control: no-store`。浏览器用 Blob 下载，错误响应按 JSON/状态码处理，不把错误页保存成 CSV。超大异步导出等实际需求出现后再增加任务和存储。

## 4 集成身份与权限

### 4.1 身份模型

集成身份独立于 `users`，包含名称、用途、负责人用户 ID、启停状态、授权组和 scope。首期仅全局 admin 创建和维护，降低委托授权复杂度；负责人用于联系与追责，不继承其个人权限。删除负责人前必须转交或停用其集成。

有效权限为：集成启用、Token 未吊销且未过期、Token scopes 与集成 scopes 的交集、资源处于当前授权组内。空授权组表示无权限，不表示所有组。首期不向集成开放未分组资源，也不提供全局 admin scope。

| Scope | 允许能力 |
|---|---|
| `assets:read` | 读取资产白名单字段 |
| `incidents:read` | 读取完整处于授权范围的事件摘要和处置结果 |
| `tickets:write` | 创建或更新本集成的工单关联 |
| `incidents:resolve` | 在另外启用回写开关后修改事件状态 |
| `suricata:write` | 写入 Suricata EVE 告警（集成须恰好授权一个组），见 [suricata.md](suricata.md) |

事件 scope 沿用“所有告警资产均在范围内”的规则，无告警或无归属告警的事件默认不向集成开放。返回 DTO 不包含原始日志、进程命令行、事件图等可能含秘密的字段；需要这些内容时应另行设计证据读取权限。

### 4.2 Token 生命周期

Token 为可识别前缀加至少 256 bit 随机秘密，创建时只显示一次，数据库只存 SHA-256 摘要与展示前缀。默认有效期 90 天、最长 365 天。轮换通过签发第二枚 Token、调用方切换、再吊销旧 Token 完成，不自动延长旧 Token。

每次请求检查当前数据库状态；吊销影响后续认证请求，已经通过认证的在途请求不能承诺即时取消。Token 不进入 URL、日志、审计详情和错误内容。界面显示到期时间、最近使用时间和最近来源地址，最近使用信息限频更新。

### 4.3 路由隔离与审计

新增 `/api/integration/v1/`，挂在专用 Bearer 中间件之后，不进入现有要求 `ent.User` 的 cookie 中间件。该入口不接受 cookie；现有浏览器 API 不接受此 Token。集成身份使用独立 context 类型，禁止伪造一个 admin 用户复用 handler。

复用资产/事件的查询和业务函数，不直接调用 HTTP handler。只提取必要的组范围谓词和结案事务服务；不重写全站 RBAC。集成审计 actor 为 `integration:<UUID>`；外部 `operator` 只能作为“调用方声明的操作人”，不能当作平台认证用户。

## 5 集成 API 契约

| 方法与路径，相对 `/api/integration/v1` | Scope | 用途 |
|---|---|---|
| `GET /assets?q=&groupId=&limit=&cursor=` | `assets:read` | 分页读取资产 |
| `GET /assets/{id}` | `assets:read` | 单资产读取 |
| `GET /incidents?status=&createdFrom=&createdTo=&limit=&cursor=` | `incidents:read` | 分页读取事件摘要 |
| `GET /incidents/{id}` | `incidents:read` | 当前摘要、版本与处置结果 |
| `PUT /incidents/{id}/tickets/{externalId}` | `tickets:write` | 绑定或更新本集成的外部工单 |
| `POST /incidents/{id}/resolution` | `incidents:resolve` | 受控状态回写 |
| `POST /suricata/events` | `suricata:write` | 写入一条 EVE 告警，不受人工调用限流 |

分页响应为 `{items, nextCursor, hasMore, observedAt}`，默认 100、最大 500；按不可变 ID 排序，cursor 绑定接口、过滤条件、集成 ID 和权限版本，使用服务端签名，权限变化后要求重新分页。列表读取的是每页当时的状态，不宣称跨页一致性快照。资产数据首期使用周期性全量核对，禁止把 `lastSeen` 当作通用修改时间。

分页过程中资产可能移组或删除；CMDB 不能仅因某次扫描缺失就立即删除资产，应二次核对并标记待确认。严格增量同步和删除 tombstone 不在首期契约内。

统一错误为 `{error:{code,message,requestId}}`：400 参数错误、401 凭据无效、403 scope 不足、404 资源不存在或不可见、409 幂等/版本冲突、422 业务限制、429 限流、503 暂时不可用。禁止返回 SQL、堆栈或秘密。

初始限流每个集成每节点 60 请求/分钟、突发 20，写接口另限每分钟 10 次；429 带 `Retry-After`。明确这是节点级限流，集群总量随节点数增加；需要全局硬额度时在入口部署统一限制，不把本机内存计数宣传为集群全局限流。

以仓库 `docs/openapi/integration-v1.yaml` 为契约交付物，包含认证、分页、全部 DTO、错误与示例；规格随实现一并交付。v1 只增可选字段，不改字段含义；破坏性变化进入 v2。浏览器 API 继续沿用现有路径。

## 6 多目标事件订阅

### 6.1 事件范围与载荷

首期只覆盖 incident 生命周期：`incident.created`、`incident.triaged`、`incident.evidence_updated`、`incident.status_changed`。新增证据仅在证据集合发生实质变化时产生事件，不把每次重复告警计数变动都外发。默认创建工单订阅选择 `triaged`，无 AI 部署可选择 `created`；生命周期订阅不继承 IM 的“良性静默”规则。

```json
{
  "schemaVersion": "1",
  "eventId": "UUID",
  "type": "incident.status_changed",
  "occurredAt": "2026-10-21T08:00:00Z",
  "incidentId": "UUID",
  "revision": 12,
  "origin": {"kind": "integration", "id": "UUID"},
  "data": {"status": "closed", "previousStatus": "triaged"}
}
```

事件只带稳定 ID、类型、版本和最小状态信息；其他类型使用对应白名单字段，不携带原始证据或自由文本研判全文。需要标题、摘要时通过授权读取 API 获取当前值。接收方按 `eventId` 去重，并以 revision 防止旧事件覆盖新状态。

订阅绑定一个集成，包含目标 URL、事件类型、授权组的子集、启停状态和签名密钥。仅向事件发生时和投递时都完全处于该范围内的事件投递。历史归属须记录在事件中；当前授权每次发送前重新检查。资产移组、集成停用等使消息失去权限时标记 `cancelled_scope`，不发送旧载荷。已经送出的消息无法召回。

### 6.2 事务发件箱

事件业务修改、incident revision 增加与 outbox 写入在同一 PostgreSQL 事务中提交。禁止先提交状态再异步插 outbox。所有事件生产路径都必须改造；仅在 HTTP handler 中挂通知不能验收。

outbox 记录不可变事件及发生时的完整组归属，分发器为符合条件的订阅创建独立 delivery。用订阅创建时间/启用区间判断资格：新订阅默认只接收其生效后的新事件；暂停期间发生的事件不自动补发，暂停前未完成投递保留。分发进度持久化，投递记录唯一键为 `(subscription_id, event_id)`。

各 server 通过 PostgreSQL `FOR UPDATE SKIP LOCKED` 领取有期限的工作租约；HTTP 请求在事务外执行，完成更新携带租约代次避免过期 worker 覆盖新结果。租约过期后重领允许重复发送。采用至少一次投递，不承诺 exactly-once，也不承诺网络到达顺序；现有 NATS 不作为这条链路的第二份持久状态。

### 6.3 重试与操作

2xx 为接收成功；接收方应先可靠保存再应答。网络错误、超时、408、429、5xx 重试，其他 4xx 进入失败待处理；3xx 不跟随，按配置错误处理。超时不能判断对方未执行，所以所有重试沿用原 eventId。

建议初值：请求超时 10 秒，退避 10 秒起、带随机抖动、最长间隔 1 小时，总窗口 24 小时且最多 20 次；429 的 `Retry-After` 受总窗口约束。达到边界进入 dead 状态，控制台显示失败原因、次数、下次重试和“可能已被对方接收”。

管理员可暂停、恢复、测试和重放失败投递。测试使用独立 `integration.test` 消息，不模拟真实安全事件。重放保留 eventId，新增 attempt；订阅 URL 变更必须显式选择是否让旧积压投向新地址，默认保留原目标配置版本，不自动转发旧数据。

### 6.4 签名和出站连接

每个订阅独立 HMAC-SHA256 密钥，使用现有凭据加密能力封存；未配置加密密钥时禁止创建含秘密的订阅。签名串精确定义为 UTF-8 `timestamp + "." + eventId + "." + rawBody`，发送时间用 Unix 秒；头部包括时间、事件 ID、key ID 和十六进制签名。每次尝试重新签名，事件正文不变。

接收方校验原始请求体、时间窗口（建议 5 分钟）并持久去重。密钥轮换允许旧新 key ID 在有限过渡期并存；到期清除旧密钥。日志不记录密钥或目标 URL 中的秘密。

目标默认要求 HTTPS；仅全局 admin 配置目标。内网对接通过明确的域名/CIDR 出站允许清单启用，禁止环回、链路本地和云元数据地址；DNS 校验与实际拨号必须使用同一已校验地址，重试重新解析校验，禁止重定向。保持 TLS 主机名校验；不能用跳过证书校验解决内网证书问题。首期不支持任意自定义认证脚本或代理继承。

## 7 工单关联与结果回写

### 7.1 所有权与字段

外部工单由 `(integration_id, external_id)` 唯一识别，一个 incident 可以关联多个系统的工单。每个集成只能改自己的关联，不能修改其他集成的外部状态。绑定字段为 `externalId, url, status, title, updatedAt`；外部状态作为不透明文本展示，不隐式映射到 incident 状态。URL 仅允许 http/https，展示时防注入，服务端不自动访问。

工单创建由适配器负责，并以 incident ID 作为其创建幂等依据。若外部平台不支持幂等创建，适配器必须先查关联或按稳定外部键核对后再重试；平台投递成功不等于工单创建成功，界面分别显示“已送达”和“已关联工单”。

### 7.2 回写请求与并发

```json
{
  "externalId": "SEC-1234",
  "expectedRevision": 12,
  "status": "closed",
  "note": "已完成修复并复核",
  "operator": "external-user-42"
}
```

写请求必须带 `Idempotency-Key`。键按集成、方法、路径隔离，保存规范化请求摘要与响应；同键同请求返回原结果，同键不同请求 409。幂等记录保留 7 天，超期键不再保证响应复用；状态写入仍受 expectedRevision 保护，工单绑定仍受唯一约束保护。

先验证身份、当前权限和请求摘要，再查可复用结果。新请求在一个事务内锁住 incident，检查版本、检查工单属于当前集成、更新状态及 revision、清理旧结案建议、写审计/outbox/幂等结果，最后提交。版本不一致返回 409，调用方必须重新读取，不自动覆盖。资源授权与资产归属变更使用一致的锁定规则，避免检查后移组造成越权写入。

默认回写只登记工单状态，不自动关闭事件。admin 必须为集成额外启用“允许回写事件状态”，并明确允许 `closed`、`false_positive`、`open` 中的哪些动作；默认只允许 `closed`。关闭/误报必须填写 1–2000 字说明；恶意判定按误报关闭还需独立授权和显式确认。重开为独立可授权动作，不能因为外部工单重新打开就自动执行。

外部结案的 `resolved_by` 使用集成身份，`resolution_source` 使用 `external_integration`。保持“非独立人工结论不进入人工案例学习”的现有查询约束；外部声称有人工处理不等于平台验证了该人员身份。主机隔离、进程终止、exec 不在本期 API 中开放。

回写仍产生状态变更事件，带可靠的 origin；由服务器填入，调用方不能伪造。适配器忽略自身已应用的 revision，而不是再次回写，防止两边反复触发。其他订阅仍可收到该变更。

## 8 数据模型与代码改动

| 表或字段 | 关键内容与约束 |
|---|---|
| `integrations` | 名称、用途、负责人、enabled、权限版本、scopes、回写策略 |
| `integration_groups` | 集成与组的唯一关联；删除组撤销关联并提升权限版本 |
| `integration_tokens` | integration_id、唯一 token_hash、前缀、scopes、到期/吊销时间、最近使用元数据 |
| `integration_subscriptions` | 集成、组子集、事件类型、启停区间、版本化目标配置、加密签名密钥 |
| `integration_events` | event_id、incident_id、revision、type、occurred_at、发生时组集合、不可变最小 payload、分发状态 |
| `integration_deliveries` | 订阅与事件唯一、目标版本、状态、下次尝试、租约及代次 |
| `integration_attempts` | delivery_id、开始/结束、HTTP 状态、受限错误摘要；不存外部完整响应正文 |
| `external_tickets` | 集成与 external_id 唯一、incident_id、外部状态、URL 和更新时间 |
| `integration_idempotency` | 集成、方法、路径、key 唯一、摘要、响应、到期时间 |
| `incidents.integration_revision` | 从 0 开始的单调版本；只对上述可订阅业务变化递增 |

已完成的投递、尝试和事件载荷默认保留 30 天；未分发/待投递记录不随普通保留期清理，超过窗口转 dead 并显示积压。仍被投递引用的事件不删除。dead 载荷满 30 天后可清理，之后不可重放，保留审计摘要；界面明确截止日期。

事件保留任务删除 incident 时，未发送记录取消，不把消失的证据重新外发；历史审计保留标识，工单关联标为源事件已清理。新表不应通过级联删除抹掉必须保留的审计记录。

| 改动位置 | 责任 |
|---|---|
| `server/internal/api/assetexport.go` | 资产导出请求、筛选、DTO 和附件响应 |
| `server/internal/integration/` | 集成认证、权限、查询 DTO、outbox 分发与投递 |
| `server/internal/api/integrations.go` | 浏览器侧集成、Token、订阅和投递管理 |
| `server/internal/incidentstate/` | 必要的事件状态事务服务、版本、审计和事件写入；命名可按实现调整 |
| `api`、`correlate`、`triage`、`janitor` 中事件修改入口 | 接入事务事件写入；含诱饵人工提交，不遗漏后台路径 |
| `server/ent/schema/` 与生成物 | 新实体、索引和 revision |
| `server/main.go` | 专用 API 路由、投递 worker 生命周期、配置装配 |
| `web/src/pages/AssetsPage.tsx` | 导出入口及状态反馈 |
| 新集成管理页与 incident 详情页 | Token、订阅、投递记录、外部工单与来源展示 |
| `web/src/i18n` 与 `docs/` | 中英文产品文案、契约、运维和适配示例 |

## 9 控制台运营体验

“系统集成”独立入口，首期仅全局 admin 管理。集成详情提供凭据、权限、订阅、投递记录四部分；创建 Token 时显示一次秘密，离开后不可再次查看。默认只读 scope，开启回写时明确展示可改变的事件状态。

投递列表支持按目标、结果和时间筛选，突出连续失败、最老待投递时间和重试次数。事件详情显示外部工单链接、外部状态、最后同步时间、回写来源；送达成功但没有工单关联时显示“等待外部系统关联”。暂停集成立即阻止新认证和新投递领取，在途 HTTP 无法撤回。

运维指标至少包括待投递数量、最老消息年龄、投递成功/失败计数、dead 数量和请求 429 计数。日志关联 requestId/eventId/deliveryId，不记录 Token 和签名秘密。若积压持续增长，界面明确标记；不能只写后台日志。

## 10 迁移与发布

阶段 A 无需新增业务表，独立上线。阶段 B 新增身份和只读 API，不改变现有登录路径。阶段 C 新增事件表、revision 与投递 worker，保留旧 IM 通知配置和行为；不把旧 `notified_at` 迁移成新订阅的成功记录。

Ent Schema.Create 继续带 `eventpart.SchemaOption`。集成 API 和对外投递默认关闭；新版本始终在业务事务内记录事件并维护本地队列。先升级全部写入节点，再开启对外 API 和投递；混合版本运行期间不得宣称完整事件流。启用时间作为覆盖起点，历史数据通过只读 API 核对，新订阅不隐式补发旧事件。

关闭新能力会停止新订阅投递和集成写入，保留表和审计。若回退到不会写 outbox 的旧二进制，重新启用后必须声明覆盖中断并做 API 对账，不能假定停机期间事件可自动补齐。不做破坏性 down migration。

## 11 验收标准

| 范围 | 必须通过的场景 |
|---|---|
| 导出 | 筛选与勾选一致、中文/换行/引号/IP 数组、CSV 公式防护、JSON 原值、空集合、边界超限、错误不伪装附件、无凭据泄漏 |
| 权限 | viewer 自有组导出、未分组隔离、跨组事件拒绝、授权变更、无权 ID 混入整次失败、Token 不能访问管理/exec API |
| 凭据 | 过期、吊销、轮换、只展示一次、日志无秘密、集成停用、负责人转交 |
| API | 游标篡改/过滤变更/权限变化、分页上限、限流、错误格式与 OpenAPI 一致 |
| 事件生产 | 人工单条/批量、AI、自动结案、新增证据、诱饵提交均覆盖；事务失败不留下事件，成功不丢事件 |
| 投递 | 服务重启、worker 崩溃、租约过期、超时但对方已收下、多节点竞争、429/5xx、永久失败、重放保留 eventId |
| 授权变化 | 事件跨组、资产移组、订阅缩权、订阅暂停恢复、目标变更、incident 清理，均不把旧数据发给新无权目标 |
| 工单回写 | 重复与冲突幂等键、旧 revision、两方同时结案、伪造 operator、关联所有权、无权限回写、无同步循环 |
| 回归 | 现有 cookie 登录、IM 通知、组权限、人工结案学习来源和 commandgate 保持原约束 |

Go 单测验证编码和签名等纯逻辑；PostgreSQL integration 测试串行 `-p 1` 验证事务、并发、权限和恢复。Web 执行类型检查、lint、build；变更涉及的 server 执行 build、vet 和测试。设计阶段不启动后台服务。

端到端验收需一个受控 Webhook 接收器和工单适配器完成“真实事件 → 去重收件 → 工单关联 → 回写 → 界面与审计”全链路；仅单测通过不算对接完成。具体厂商凭据、状态映射及外部人的身份可信度在连接该系统前确定，不阻塞通用接口开发。

## 12 实施顺序

1. 完成 A：资产导出和边界测试，先交付可直接使用的运营能力。
2. 完成 B：集成身份、只读 API 和 OpenAPI，验证外部程序不依赖 cookie。
3. 完成 C 的生产链：所有事件变更入口事务化、revision、outbox、多目标投递与故障恢复。
4. 完成 C 的回写链：工单关联、幂等、冲突保护、界面和受控适配器端到端验收。

每阶段独立提交、验证；本设计不包含自动 push 或部署。严格增量 CMDB 同步、全量原始日志导出及厂商专用连接器按后续实际需求扩展。

## 当前实施与验证记录

截至本次实现，关联引擎、人工单条/批量结案、AI 研判、自动结案和诱饵事件创建已将
incident 变更与 IntegrationEvent 发件箱放入同一事务。只读 API 返回 `revision`。
事件记录随业务事务生成，运行时对外投递由 INTEGRATION_WEBHOOK_ENABLED 控制，默认关闭；旧 IM 通知仍独立运行。

已通过：发件箱失败/回滚原子性、历史组快照、受控 HTTPS 接收器签名验证、503 重试、
租约过期恢复、过期 worker 结果拒绝、移组后取消投递。关联与研判、janitor 的 PostgreSQL
回归以及人工单条/批量结案、诱饵复核回归均通过。

订阅 CRUD、暂停轮换、测试/重放及投递查询、worker 配置、工单关联与幂等回写、控制台入口
和机器 OpenAPI 已接入。受控 HTTPS 适配器完整链路测试覆盖首次处理成功但应答失败后的重复投递：
工单、事件状态与审计均未重复写入。该测试不代表已连接具体厂商的生产工单系统。

保留期清理、源事件删除标记、投递分页/筛选/尝试明细、积压统计、Prometheus 指标和两份部署编排的环境变量透传已完成。
关闭出站时仍维护本地队列；暂停不延长 24 小时重试窗口。轮换必须先暂停并等待有效在途租约结束，
随后待发记录使用新 key ID；接收方按部署说明短时兼容旧密钥，用于已发出的请求。

本地验证结果：

- server 全量 `go test ./...`、`go build ./...`、`go vet ./...` 通过。
- 独立 PostgreSQL 测试库的导出、身份管理、负责人/组生命周期、订阅管理、游标/权限、
  幂等/版本回写、保留期与受控 HTTPS 链路测试通过。未使用生产数据库。
- 并发领取、历史启用区间、旧目标版本、重复分发、租约恢复及过期 worker 拒绝通过；
  302 不跟随、400 永久失败、408/429 重试、Retry-After、20 次/24 小时边界测试通过。
- 前端 build/lint 通过；lint 存在原有 Fast Refresh 警告。短时 Chromium 检查了订阅创建、
  一次性密钥、投递明细、移动端渲染与资产下载，无页面异常。该浏览器检查使用模拟 API 数据；
  HTTPS 投递与回写由真实 PostgreSQL 后端测试独立验证，不声称完整部署的浏览器端到端验收。
- 未运行生产负载压测、真实厂商对接或产品部署；同步导出上限仍是保护值而非性能承诺。

接入实际工单平台时，适配器负责持久收件去重、厂商认证、字段映射与循环抑制。
按本设计第 11 节在实际部署环境复验完整链路后，才能宣布该厂商对接上线。
