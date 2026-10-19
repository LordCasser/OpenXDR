# 身份来源与关联（开发中）

当前起点是已部署的端点登录遥测，不把同名账号自动合并成全局身份。

## Windows Security 登录

采集端从真实 4624/4625 字段保留：

| 原始字段 | 归一化字段 | 语义 |
| --- | --- | --- |
| EventID | event_id | 4624 成功或 4625 失败 |
| Security 日志通道 | log_name | 来源为 Security |
| TargetUserName | user.name | 被登录账号显示名 |
| TargetUserSid | user.uid | 原始 SID；未知 SID S-1-0-0 不作为身份 |
| TargetDomainName | user.domain | 日志自报的域或本机名称，不据此推断目录权威 |
| TargetLogonId | session.uid | 仅成功登录的非零目标 Logon ID，规范成小写十六进制 |

字段依据：[Microsoft 4624](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624)、
[Microsoft 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)。
失败事件中的 SubjectLogonId 不是新建目标会话，不能把它当成目标用户登录成功的关联标识。

服务端 `internal/identity.WindowsLoginFromRaw` 校验接入来源、资产 OS、事件类别、日志类型及成功/失败一致性。
SID 使用常见十进制表示并校验数值范围；未知 SID 不降级为用户名身份。账号键当前限定在 `(group, asset, SID)` 内，
目录权威未核实前不做跨设备合并。Logon ID 仅保留为观察值；缺少 OS 启动边界和会话结束事件时，不能构造永久会话身份。

## 事务入库

生产 Processor 在原始事件首次插入后调用身份观察，新增 `identity_observations`：
每条记录绑定来源 event_id、数据库资产、处理时归组、规范化 SID、名称/域、观察到的目标 Logon ID 及成功标记。
同一事件重投不会新增记录，换组后重投旧事件也不会改写原观察归组。当前 OS 和组从数据库资产行读取并锁定，
不采纳 raw 自报的组/资产，也不只凭信封 OS 判断 Windows 来源。

状态区分 `observed`、`missing_sid`、`unscoped` 和 `invalid`；`observed` 仅表示字段可归一化，
不是成功认证的别名，认证结果另看 success。失败登录不记录目标会话，缺少 SID 不按名称构造账号键。
身份解析错误会记录 invalid 并保留原文；数据库写入失败则整笔事件事务回滚并可重试。
原始事件删除时级联删除观察，避免留下无法追溯来源的关系。

这是观察记录，不是完整账号目录或跨重启会话表。

## 授权查询

`GET /api/identity-observations?assetId=<UUID>` 返回 `{items, truncated}`。必须指定非零资产 ID；
`from`/`to` 接受 RFC3339 时间，默认最近 24 小时；`limit` 默认 100，范围 1–200。
按事件时间、事件 ID 倒序，额外读取一条判断是否截断；截断时可收窄时间范围。无权限或没有记录均返回空数组。

每条观察包含 eventId、assetId、历史 groupId、ts、sid、name、domain、logonId、success、state 和 detail。
未知字段返回 null，不把未知认证结果当作失败，也不返回未校验的原始事件体。
查询在同一条 SQL 中同时检查当前成员资格、观察历史归组和资产当前归组：
换组后，旧组失去当前资产权限，新组也不会继承旧组观察；同时属于两个组的用户可读取两边。
未归组观察或当前未归组资产仅全局管理员可读。接口沿用登录中间件。

## 当前验证范围

- Windows 采集解析新增 SID/域/目标会话测试，通过 Windows GNU 全目标 clippy；尚未在 Windows 实机执行。
- Go 归一化单测覆盖身份字段、失败登录不生成会话、缺少 SID 不按名字补全、组/资产隔离、错误来源和字段冲突。
- 现有机器/服务账号过滤保持原行为，因此不能声称已覆盖全部域身份活动。
- 真实 PostgreSQL 已验证观察事务、失败回滚/恢复重试、设备/组隔离、换组重投、坏字段保留原文、源事件级联删除和日志自报归属不被采信。
- 尚未实现账号目录实体和跨重启会话关系。Linux/目录服务来源和跨系统关联仍待实施。

- 身份查询真实 PostgreSQL 专项覆盖资产换组、双组成员、成员资格撤销、管理员/未归组边界、失败登录空字段、数量截断及参数校验。

## 资产详情展示

资产详情新增「身份观察」标签页，只在打开时查询。默认最近 24 小时，可切换 1/6/24/72/168 小时，
每 15 秒刷新；最多展示最新 200 条，截断时明确提示缩短时间范围。表格区分登录成功、失败和结果未知，
展开可查看 SID、域、目标 Logon ID、历史归组和可复制的来源事件 ID；目前不提供该事件原文的直接钻取。

未知字段不补造，空列表提示可能缺少支持的遥测，查询失败独立显示重试入口。
查询键包含当前用户、角色、组成员信息和资产归组；这些信息变化时不复用旧结果，关闭标签页后移除查询缓存。
这不替代服务端权限检查，也不能撤回用户已经看到的数据。中文与英文文案同步维护。

前端类型检查、生产构建和 lint 通过；尚未做浏览器交互或生产验收。

## 多目录接入（开发中）

按多身份源实现，不绑定单一厂商。计划覆盖 AD/LDAP、Entra ID、Keycloak 和端点本地账号；
当前新增代码实现 Keycloak、Entra ID、AD/LDAP 账号读取及通用存储；本地账号目录、目录组/成员、设备和会话关系尚未实现。

`internal/identity/directory` 的来源包含固定 ID、授权资产组、类型和权威地址。
账号 ID 由上述来源命名空间与来源内稳定 ID 构造，不使用用户名或邮箱；不同 realm、目录或授权组不会自动合并。
来源登记后不能原地换组或换权威地址，需要单独登记。来源表和读取结果均不包含凭据。

Keycloak 读取契约参考 [Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/index.html)：
`GET /admin/realms/{realm}/users` 使用 first/max 分页，realm 为名称。
适配器要求 HTTPS，支持服务根的 /auth 前缀，从调用方取得短期 Bearer token，拒绝 HTTP 重定向。
每页最多 100 条、2 MiB，整次最多 10000 账号/1000 页/2 分钟，单请求最长 30 秒。
短页仍继续，直到空数组结束；HTTP 错误、重复 ID、坏字段、超限或取消均使整次读取失败，不返回部分成功列表。
不读取密码、会话令牌、角色和凭据内容；错误不回显响应体或令牌提供器原始错误。

`RegisterSource` 供可信配置入口登记来源，`SaveScan` 在事务中保存账号与本次成功枚举时间。
同来源行锁及开始时间阻止旧枚举覆盖已保存的新版本，时间统一到 PostgreSQL 微秒精度。
重命名沿用稳定 ID，enabled 区分 true/false/null；本轮缺席账号保留上次 observed_at，不推断停用或删除。
分页枚举不具有目录端事务快照语义，权限过滤或分页期间的变化仍可能造成遗漏，因此不能按缺席做破坏性同步。

Schema 随服务端启动初始化。已接入可选环境配置与定时同步；当前没有目录配置 API；已提供下文只读查询接口和组管理页状态标签。
默认未配置时不向目录发请求；通用存储仅由内部受信入口使用，尚未授予 Pi 或客户端直接写入能力。
真实目录配置及生产验收仍待完成，不能将本地 HTTPS 契约测试视为实际 Keycloak 兼容验收。

### Entra ID 账号适配器

`NewEntra` 接受固定租户 UUID 和管理员配置的 Graph HTTPS 根地址，可配置不同云端点。
先通过 `/v1.0/organization?$select=id` 校验返回的唯一组织 ID，再读取 `/v1.0/users`。
整次枚举复用同一个短期令牌，避免令牌提供器在分页间切换租户；令牌过期报错，不保存部分结果。
账号使用 object ID，UPN 仅作名称，accountEnabled 缺省/null 保留未知。

按照 Graph 返回的完整 `@odata.nextLink` 继续请求，包括空页后的下一页；不自行解析或重建 skiptoken。
分页地址必须保持原 HTTPS authority 和 `/v1.0/users` 路径，拒绝凭据、fragment、路径编码变体、跨服务和循环链接；
HTTP 跳转一律拒绝。沿用单页 2 MiB、100 账号、整次 10000 账号/1000 页/2 分钟和单请求 30 秒上限。
超限、429、权限不足、坏字段或取消均使本次枚举失败，没有自动重试或增量 delta 游标。

应用权限需满足用户枚举和 organization 读取；通常分别为 User.Read.All、Organization.Read.All。
accountEnabled 的可读性还应按租户授权及当前 Graph 文档确认；没有返回状态时不推断停用。
环境配置、定时同步与客户端凭据取令牌已接入；真实租户验收尚未完成，默认未配置时不访问目录。

协议依据：[用户枚举](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0)、
[组织查询](https://learn.microsoft.com/en-us/graph/api/organization-list?view=graph-rest-1.0)、
[Graph 分页](https://learn.microsoft.com/en-us/graph/paging)。

### AD / LDAP 账号适配器

`NewLDAP` 接受来源/资产组 ID、服务地址、搜索 Base DN、profile、可选 filter 和凭据提供器。
支持 `ldaps://`（默认 636）与 `ldap://` 强制 StartTLS（默认 389）；TLS 最低 1.2，验证服务地址的证书名称，
支持调用方提供自定义根 CA，拒绝 InsecureSkipVerify。TLS 失败不发送明文 Bind，不允许空密码匿名退化。
绑定账号可由凭据管理器提供 DN 或 UPN；目前实现 simple bind，未实现 Kerberos/SASL。

- `ad`：默认过滤 person/user，读取 objectGUID、objectSid、sAMAccountName、userAccountControl。
  objectGUID 按 AD 二进制 GUID 字节序转换为稳定 UUID；用户名/DN 变化不改变身份。
  ACCOUNTDISABLE 位决定 enabled，缺少该属性保留未知；不把账号锁定、密码过期等状态混为停用。
- `ldap`：默认过滤 inetOrgPerson，读取 entryUUID 和 uid；不依赖可变 DN 构造身份。
  目前要求 RFC 4530 entryUUID，不支持仅有 DN/自定义 UUID 属性的目录；无通用停用属性，enabled 保留未知。

搜索不解引用 alias、不跟随 referral。分页请求 100 条，要求响应携带 paging control，空页有 cookie 时继续；
缺失控制、重复 cookie、重复稳定 ID、属性歧义、服务器错误或超过 10000 账号/1000 页均返回失败。
整次最多 2 分钟，单 LDAP 请求超时 30 秒，取消关闭连接；服务器不遵守分页时启用库的 10001 条解析数量限制，
返回页超过 100 条即拒绝。没有额外实现单条 BER 字节预算，不宣称与 HTTP 适配器相同的 2 MiB 响应限制。
完整成功结果才交给通用事务存储，缺席仍不表示删除。来源按服务端地址与 Base DN 区分，尚不自动合并不同域控别名。

本地验证包含账号/分页契约、GUID 字节序、重命名、停用/未知、容量与取消；真实 TCP 测试确认 StartTLS 先于 Bind，
本地模拟 LDAP 服务通过真实 TLS socket 完成绑定和搜索。它们不替代真实 AD/OpenLDAP、成功 StartTLS 或 Kerberos 验收。
依赖 go-ldap v3.4.14，保留项目 Go 1.25.9；依赖要求将 x/net 更新到 v0.57.0。

字段依据：[entryUUID RFC 4530](https://www.rfc-editor.org/rfc/rfc4530)、
[AD UserAccountControl](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)。

### 单次同步与运行记录

`SyncOnce` 将已经登记的来源与任一 Reader 接起来：先在数据库验证来源 ID、资产组、类型和权威地址，
创建 running 记录后才访问目录。返回来源不一致、无效结果、读取失败、超时/取消均不入库账号。
成功时账号、来源成功枚举时间及 succeeded 记录同事务提交，错误不前移成功时间。
失败记录仅保存 read_failed/source_mismatch/invalid_result/stale_scan/persist_failed/canceled 分类，
不保存适配器原始错误、凭据或目录响应体。运行记录包含开始/结束时间和成功读取账号数。

取消后用独立五秒上下文尝试记录失败；数据库不可用时返回状态未确认，不能假称失败记录已经持久化。
提交结果不确定时先通过条件更新和读取核对运行状态，已经 succeeded 的记录不会被覆盖成 failed。
进程中断可能短暂留下 running，由下文的维护任务回收；运行记录也随来源/组删除。

并发读取是只读操作，允许多个调用同时进行，来源锁和开始时间阻止旧结果覆盖新结果；后台调度复用现有集群 leader 锁。
单次同步函数本身不自动运行，服务端只对显式配置的来源启动后台任务。

## 启动配置与定时同步

设置 `IDENTITY_SOURCES_JSON` 为严格 JSON 数组，最多 32 个来源/64 KiB。空字符串或 `[]` 关闭同步；
未知字段、重复来源 ID、缺失凭据引用、非法周期或来源绑定冲突拒绝启动。
组必须预先存在；首次部署先不配置目录，在控制台建组后填入真实 UUID 并重启。
同一来源 ID 不允许改组/类型/权威地址；删除环境定义只停止同步，不自动删除历史账号。

例如 Keycloak 的来源定义（UUID 为占位，需替换；这里只引用凭据环境变量名）：

```json
[{
  "id": "11111111-1111-4111-8111-111111111111",
  "groupId": "22222222-2222-4222-8222-222222222222",
  "kind": "keycloak",
  "url": "https://sso.example.invalid",
  "realm": "company",
  "tokenEnv": "DIRECTORY_TOKEN",
  "intervalSeconds": 900
}]
```

Entra 使用 `kind: entra`、Graph 根 URL、`tenantId` 和 `tokenEnv`，不填 realm。
AD/LDAP 使用 `kind: ad` 或 `ldap`、`url`、`baseDN`、`bindUserEnv`、`bindPasswordEnv`，可选 `filter`。
所有来源可用 `caEnv` 引用额外 PEM 根证书；CA 在启动时加载。同步周期默认 900 秒，范围 300–86400 秒。
HTTP 目录可选择静态 tokenEnv 或下文的 OAuth 客户端凭据模式；静态令牌过期会记录失败，更新环境后需重启服务。
LDAP 绑定密码同样在环境中提供，不存入数据库。容器内必须显式注入引用的环境变量；仅写在宿主机 .env 不会自动传入。
Compose 模板只透传来源定义，凭据请通过本地 override 的 environment/env_file 注入，文件不要提交仓库。

后台复用 `identity-directories` 集群任务锁；启动/取得租约后立即尝试一次，随后各来源在本轮完成后等待完整周期。
最多四个并发读取，不追补错过的周期。租约失效取消工作者；集群各节点应保持相同配置。
当前不是带 fencing token 的恰好一次调度，短暂租约交接可能重复只读枚举，入库仍由来源锁和扫描版本保护。
日志只输出来源 ID、运行 ID、状态、错误分类及账号数，不输出配置或凭据。没有部署或真实目录验收。

### OAuth 客户端凭据模式

Keycloak/Entra 可用 `oauth` 替代 `tokenEnv`，两者互斥。客户端密钥只引用环境变量：

```json
"oauth": {
  "tokenURL": "https://sso.example.invalid/realms/company/protocol/openid-connect/token",
  "clientId": "openxdr-reader",
  "clientSecretEnv": "DIRECTORY_CLIENT_SECRET"
}
```

Entra 显式填写对应云/租户的 tokenURL，且必须配置 scope；公共云示例是
`https://login.microsoftonline.com/<tenant UUID>/oauth2/v2.0/token` 与 `https://graph.microsoft.com/.default`。
端点来自管理员启动配置，不自动发现或从不可信目录响应中取得。应用必须已被授予所需只读权限。

使用 HTTPS POST 表单发送 client_credentials/client_id/client_secret/可选 scope，拒绝跳转。
令牌响应最多 128 KiB，校验 Bearer 类型、非空令牌和正整数有效期；失败不回显响应体、令牌或客户端密钥。
有效令牌按来源实例仅缓存在内存，提前 30 秒停止复用，最多缓存一小时；短于 30 秒的令牌仅用于当次调用。
并发取令牌串行协调，等待可以取消；密钥值变化使旧缓存失效。容器环境本身更新仍需重启。
不持久化 access_token/refresh_token，不使用 refresh_token，也未实现证书断言、工作负载联合身份或托管身份。
Entra 每次扫描固定同一枚令牌，扫描中到期会失败，下一周期重新获取；不对目录 401 自动重放分页。

本地 HTTPS 已验证配置/CA 加载到 OAuth、缓存及 Keycloak 分页的完整读取链；没有真实租户、权限配置或长期运行验收。
协议依据：[Microsoft client credentials](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)、
[Keycloak OIDC](https://www.keycloak.org/securing-apps/oidc-layers)。

## 目录与同步状态查询

以下接口只读、需要登录，均在 SQL 中检查数据库当前用户角色及来源所属组的当前成员资格。
不会信任会话缓存中的管理员角色；组外/来源不存在均返回空 items，不泄露来源是否存在。
返回存储元数据，不返回环境变量名、客户端密钥、绑定密码、访问令牌或原始目录响应。

- `GET /api/identity-directories?groupId=<UUID>`：组必填，返回来源类型、权威地址、最后成功枚举起止时间，
  以及最近一次运行 ID/状态/错误分类/起止时间。从未同步的字段为 null；最新失败不覆盖最后成功时间。
- `GET /api/identity-directories/<sourceId>/accounts`：账号稳定 ID、来源 ID、外部 ID、名称、enabled 和 observedAt。
  按内部账号 ID 排序，返回 `{items,truncated,next}`；下一页将 next 传入 after。
  翻页期间目录可能变化，不承诺跨请求事务快照。enabled=null 是未知，observedAt 是最后观察时间，不能解释成当前在线。
- `GET /api/identity-directories/<sourceId>/runs`：最近运行记录，按开始时间/ID 倒序，最多返回最近 200 条。

limit 默认 100，范围 1–200。来源与运行列表返回 `{items,truncated}`，账号列表另外返回下一页游标。
读取异常返回错误而非空列表；没有记录不等于同步成功或目录为空。
历史来源还在数据库中不代表现在仍配置了同步；running 只是保存的状态，不证明进程仍存活，超过提交期限后由维护任务回收。
接口没有写入、触发同步、修改凭据或自动重试能力；组管理页已接入下文的目录状态标签。

## 组管理页目录状态

在组管理抽屉选择「身份目录」，再选择来源查看账号与同步记录。标签按需加载，来源与运行记录每 15 秒刷新；
账号每页 25 条使用服务器游标，支持上一页、下一页、返回首页和刷新当前页。
切换来源或身份/组权限信息变化时重建详情状态；查询键包含用户、角色、成员关系和来源归组，卸载后移除查询缓存。

来源表分别展示最后成功时间和最新运行状态；详情明确提示最近失败时账号可能来自旧同步、running 不证明工作者存活。
账号区分启用/停用/未知并展示观察时间，展开可复制外部稳定 ID。运行记录只在成功时显示账号数，失败不显示假零账号。
独立处理加载错误和空列表，来源/运行截断明确提示。此处只读，不提供修改配置或手动触发同步按钮。
中文与英文同步维护；类型检查、构建和 lint 通过，未做浏览器交互或生产验收。

### AD SID 关联依据

AD 读取额外保留 objectSid，按 Windows 二进制 SID 结构解码为规范文本；端点登录与目录共用同一套文本校验。
缺失字段保持空值，损坏、多值、空 SID 或同一次扫描内多个账号重复 SID 会拒绝本轮结果；普通 LDAP/HTTP 来源不能自报 AD SID。
账号表增加可空 windows_sid；新一轮明确未返回 SID 时清空旧值，不把旧值冒充本轮观察。
账号查询返回 windowsSid，详情展示 SID 与来源内稳定 ID；GUID 仍是 AD 账号身份主键，不用 SID 或显示名跨目录合并。

这一步只保存关联依据，尚未自动将 Windows 登录事件关联到目录账号。同名、域名相似以及单个 SID 命中都尚未转换成全局身份图。
同一账号可以被多个目录来源重复观察，后续关联必须保留来源、时间和歧义，不能随意选第一条。
结构依据：[SID](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid)、
[objectSid](https://learn.microsoft.com/en-us/windows/win32/adschema/a-objectsid)。

## 登录记录的目录账号候选

`GET /api/identity-observations/<eventId>/directory-accounts` 将身份观察的 SID 与同一历史组内 AD 账号 SID 精确匹配。
前提是观察状态为 observed 且目录提供了 SID；不使用名称、域名或 SIDHistory 猜测关系。
这是当前目录观察与历史登录记录的候选关系，不是事件当时账号归属的证明，也不表示登录成功或自动合并了身份。

单条 SQL 同时核对数据库当前角色、观察历史组、资产当前组；候选目录必须在观察历史组内。
组外或观察不存在统一 404，缺少匹配返回空数组。最多 20 条，额外读取一条判断 truncated，多个候选标 ambiguous。
候选返回来源、账号 ID、名称、SID、状态、观察时间和最后成功同步时间；seenInLatestSync 仅表示其观察时间等于来源最近成功扫描时间，
不证明账号当前在线或目录仍在启用同步。后续空扫描保留的账号仍可作为历史候选，但标为未在最近扫描出现。

资产详情「身份观察」展开记录后，点击查询按钮才读取候选；展示来源与时间、歧义/截断提示，未知或加载失败独立处理。
查询缓存按当前身份、成员关系、资产归组及事件隔离；权限仍由后端数据库校验。中文与英文同步。
原身份观察列表也改为查询数据库当前管理员角色，避免管理员降权后继续依赖旧会话角色。
此步骤没有写入自动身份边、全局主体或跨重启会话。

## 运行期限与历史清理

单次同步总上下文最长三分钟（包含数据库操作），目录读取仍最长两分钟。
成功提交在数据库中额外检查运行开始时间不得早于五分钟前，且状态仍为 running；过期或已回收运行的账号更新和成功时间全部回滚。
时间条件使用数据库时钟，不依赖工作节点时钟来判定是否允许提交。

独立的 identity-maintenance 集群任务每分钟尝试维护，即使已经移除所有目录配置也运行；它不访问外部目录。
超过五分钟的 running 记录改为 failed/deadline_exceeded，表示超过提交期限，不推断目录断线或远端失败。
每轮过期回收最多 1000 条，跳过持锁行。维护延迟可能让 running 暂时保留，但提交期限仍独立生效。

IDENTITY_RUN_RETENTION_DAYS 默认 30，允许 0–3650；0 仅关闭历史删除，不关闭过期回收。
终态记录按结束时间清理，每轮最多 1000 条并跳过持锁行，每来源按开始时间/ID 排序的最新记录始终保留。
来源与账号、最近成功时间不随运行历史清理；不存在历史运行不等于从未同步。失败状态含“超过提交期限”的中英文说明。
真实 PostgreSQL 测试验证回收前/后均拒绝迟到提交、事务回滚、持锁跳过、最新记录保留、关闭删除和批次上限；不替代进程崩溃实机验收。

## Linux 本地账号采集（开发中）

Linux 设备清单采集读取 `/etc/passwd`，只上报 name、UID、GID 和 shell，不发送 password、GECOS 或 home 字段，
不读取 shadow，不通过 NSS/getent 发起目录网络查询。UID 仅在当前主机内有意义，多个不同账号名共享 UID 合法，不按 UID 去重。
用户名重复、坏字段、非 UTF-8、文件超过 1 MiB 或账号超过 512 条会使本次账号清单 unavailable，不截断成完整清单。

采集复用 collect_inventory 和现有设备清单循环（60 秒）；账号内容或可用状态变化也触发清单上报，无变化时仍沿用六小时补报。
事件保留 class_uid=5001/activity_id=2，新增 device.local_accounts：version=1、source=etc-passwd、state，
成功时携带 items，失败不带 items。缺失、空清单和失败不同。设备监听清单读取失败时本轮仍随既有设备清单循环重试，
尚未把本地账号改为独立采集线程。

新增 local-accounts 健康状态，前端显示本地账号清单能力。升级须先升级 server，再升级 agent；旧 server 的严格组件名单会拒绝新健康字段。
服务端在原始事件首次插入的同一事务中提取账号快照与逐账号观察，尚未与 Linux 登录记录关联。
现有 wtmp/sshd 登录记录只有用户名，不能借当前 passwd 快照倒推出事件当时的 UID，也不把 shell 值当作账号启用状态。
容器中的清单只代表 agent 所见文件系统，不代表宿主机或所有容器账号；不支持 NIS 兼容条目或完整 NSS 目录。

### 本地账号观察入库

`identity_local_snapshots` 绑定原事件与资产，保留接收时的数据库归组、etc-passwd 来源和 observed/unavailable/invalid 状态；
`identity_local_accounts` 以事件 ID 与账号名为键保存 UID/GID/shell，不构造跨时间稳定主体。
空 observed 快照没有账号行；坏清单整体标 invalid，原事件继续保存，错误原文不落身份表。
账号、快照和原事件同事务提交，写入错误全部回滚；重复事件不更新归组，迟到清单独立保存，不覆盖新观察。
归组仅代表首次接收时归属，不能证明离线采集当时的组。原事件或资产删除会级联删除相关观察，遵循原始证据保留期。
目前提供快照列表与详情 API 和资产详情标签，Linux 登录关联仍待接入；不存在账号行不能解释为账号已删除。

### 本地账号快照查询

`GET /api/local-account-snapshots?assetId=<uuid>` 返回最近 24 小时快照；支持 from/to RFC3339 时间与 limit（默认 100，上限 200）。
结果包含 items/truncated，按事件时间与 ID 倒序；条目包含 eventId、assetId、groupId、ts、state、source、accountCount。
只有 observed 状态返回账号数，失败/坏数据返回 null，避免将不可用误作零账号。
SQL 同时检查数据库当前用户角色、历史组和当前资产组权限；不可见和不存在均为空列表，未登录拒绝。
这是有界历史列表，尚无历史游标。

`GET /api/local-account-snapshots/{eventId}` 按需返回快照元数据及 items（名称、UID、GID、shell），
在单条 SQL 中重新核对当前角色、历史组和当前资产组；不可见或不存在统一 404。
成功清单返回数组，成功空清单返回 []；unavailable/invalid 的 items 和 accountCount 均为 null。
账号按名称排序；正常接入清单上限为 512 个账号，不返回原始事件或凭据，也不推断账号启用状态。

资产详情新增「本地账号清单」标签，按需挂载，默认查询 24 小时，可切换时间范围或手动刷新；列表每 15 秒刷新。
展开快照才请求账号详情，账号本地分页；读取失败可独立重试，采集失败与成功空清单分别展示。
查询缓存按用户、角色、成员关系和资产归组隔离，切换范围重建表格；中英文同步。
未进行浏览器或生产验收，不能用页面编译通过替代实际交互验证。

### Linux 登录观察

Agent/Linux/class 3002 的登录事件进入既有身份观察事务与列表，保留用户名和成功/失败；
state=missing_uid 表示用户名观察，账号键、SID、Logon ID 留空。Windows event_id/log_name 格式不进入 Linux 解析。
不使用日志自报 UID/session，也不以当前 passwd 快照反推历史 UID；失败中的名字不证明账号存在。
坏字段标 invalid 并保留原事件，非登录活动不生成观察。前端状态与说明已同步中英文。
这一步尚未关联本地清单候选、目录主体或认证会话。

### Linux 同名历史清单候选

`GET /api/identity-observations/{eventId}/local-accounts` 返回 items/truncated。仅 missing_uid 观察参与，
按同资产、同历史组和账号名精确匹配登录事件前 24 小时（含端点）的成功清单；未来及更早快照排除。
候选带快照 eventId、observedAt、name、uid、gid、shell，按时间/ID 倒序最多 20 条，重复历史观察不合并。
它不是最近完整清单，也不证明账号在登录时仍存在或 UID 未变；后续失败/空清单不会抹掉这些历史候选。
数据库当前角色与历史/当前双组权限同 SQL 校验；不可见观察返回 404，可见但不匹配返回空数组。
未建立身份等价边，不更改登录结果或 missing_uid 状态；前端已提供按需查询入口。

Linux missing_uid 登录观察展开后，可按需查询历史同名账号，展示快照时间、名称、UID/GID、shell 和来源事件。
查询错误可重试，空结果不解释为账号不存在；保留截断提示，文案明确候选不是最近完整清单或已确认身份。
缓存按用户、角色、成员关系与资产归组隔离；中英文同步。尚无浏览器验收。
