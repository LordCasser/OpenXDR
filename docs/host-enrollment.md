# 文档导入与主机纳管

状态：已实现文档预览、资产与凭据入库、显式 SSH 安装入口；真实 Linux/Windows
远程安装仍需目标环境验收。导入成功、安装脚本成功、Agent 在线是三个不同状态。

## 操作流程

1. 通过可信 HTTPS 打开控制台，在资产页选择「从文档导入」和目标组。
2. 上传或粘贴 Markdown、YAML、JSON 文档，点击预览。最多 1 MiB、100 台主机。
3. 核对主机名、地址、系统、用户、凭据类型后确认入库。密码、私钥不出现在预览结果中。
4. 主机先显示「待纳管」。凭据页可删除凭据，也可单独点击「使用凭据纳管」。
5. 提供通过可信渠道独立核对的 SSH SHA256 主机指纹，再确认安装。
6. 安装脚本完成后等待 Agent 的 mTLS 注册和心跳；不能把安装响应当成已经在线。

只有该组 admin 或全局 admin 可导入、列出凭据元数据、删除凭据和发起安装。
导入本身不连接主机，也不会执行文档中的命令。模型不参与凭据识别，不接触凭据。

## 文档格式

支持结构化字段，不能确认主机与凭据对应关系的自由叙述需先整理成以下格式。
不会因为密码、私钥出现在文档中而拒绝整份文档，也不会把原文当普通知识文档保存。

Markdown 主机表格：

```markdown
| 主机名 | IP | 系统 | 端口 | 账号 | 密码 |
|---|---|---|---|---|---|
| app-01 | 192.0.2.10 | linux | 22 | root | 示例占位密码 |
| win-01 | 192.0.2.20 | windows | 22 | Administrator | 示例占位密码 |
```

YAML 文件、Markdown 内的 yaml/yml 代码块，以及等价 JSON 的 `hosts` 列表：

```yaml
hosts:
  - hostname: app-01
    address: 192.0.2.10
    os: linux
    port: 22
    username: root
    password: "示例占位密码"
  - hostname: app-02
    address: 192.0.2.11
    os: linux
    username: deploy
    private_key: |
      此处填写完整 PEM/OpenSSH 私钥；本占位文本不可导入
    passphrase: "仅加密私钥需要"
```

字段：`hostname`、`address`、`os`、`port`、`username`、`password`、`private_key`、
`passphrase`、`host_key`。`host_key` 可选，必须是有效 `SHA256:…` SSH 主机指纹。
密码与私钥二选一；可不提供凭据，只导入资产。含竖线、多行的密码或私钥使用 YAML，
不要塞进 Markdown 表格。私钥会在导入时验证格式和解密口令。

主机名省略时使用地址，但远程纳管要求其与目标 `hostname` 一致；IPv6 地址请显式填写
合法主机名。已有同组资产且尚无凭据时可补充凭据，保留已有资产字段。已有凭据、跨组或未分组资产冲突时整批拒绝，不覆盖已有身份、不跨组挪用资产、不部分提交。

## 凭据存储

- 配置 `HOST_CREDENTIAL_KEY`：base64 编码的 32 字节随机密钥，可用 `openssl rand -base64 32`
  生成。通过受保护的环境变量注入，不提交仓库，不存入普通设置表。
- 使用 AES-256-GCM，每条凭据独立随机 nonce。附加认证数据绑定凭据 ID、资产、组、
  地址、端口、用户名、类型和主机指纹，调换密文或连接参数会导致解密失败。
- 数据库存储在独立的 `host_credentials` 表；Ent 敏感字段、API DTO 和模型只读视图
  都不暴露密文或明文。数据库备份仍按敏感数据管理。
- 原始文档不入库；审计只记录操作、资产/组标识和数量，不记录凭据、文档或远程输出。
- 主机移组、移出组或删除组时删除对应凭据，不把旧组授权下的登录身份自动交给新组。
- HA 各节点必须配置同一密钥，密钥与数据库分开备份。当前不提供在线轮换工具；
  不得直接替换密钥，否则已有凭据不能解密。丢失密钥后需删除旧凭据并重新导入；已有同组资产可以重新关联凭据。

## 使用凭据安装

服务端需要：

| 环境变量 | 默认值 | 用途 |
|---|---|---|
| `HOST_CREDENTIAL_KEY` | 空 | 空时禁止导入含凭据的文档；纯资产导入仍可用 |
| `ENROLL_SSH_ENABLED` | `false` | 显式开启使用保存凭据进行 SSH 安装 |
| `ENROLL_PUBLIC_URL` | 空 | 主机可访问的可信 HTTPS 控制台地址，用于下载 Agent 和证书注册 |
| `ENROLL_GRPC_URL` | 空 | Agent 可访问的 gRPC 地址；生产使用 mTLS |
| `TLS_CA_KEY_FILE` | 空 | mTLS 签发密钥，参见 [部署与使用手册](deployment.md#添加主机) |
| `AGENT_DIST_DIR` | 空 | 各平台 Agent 安装包目录 |

SSH 纳管要求 mTLS 在线签发可用。Linux 需要 root，或具有免交互 sudo 权限的账号。Windows 需要已启用 OpenSSH、
可使用 PowerShell 的管理员账号。本轮不提供 WinRM、RDP 或交互式 sudo 密码提权。
这些 Windows 凭据仍可入库，但未配置 OpenSSH 时不能自动安装。

连接固定目标并核验 SSH 主机指纹，然后核对实际主机名；仅执行平台内置安装脚本。
接入令牌绑定组、有效期 5 分钟，调用结束即撤销。每条凭据有数据库租约，避免 HA
节点重复发起安装。安装过程最多两分钟，客户端中断会关闭连接；超时、连接中断或
脚本失败均表示**未确认完成**，应先核对服务和平台心跳，不能断言没有副作用后盲目重试。
远程 stdout/stderr 不回传前端或写入日志。

## 安装与升级失败保护

Agent 将待签私钥写入 `agent.key.pending`；申请被拒绝不覆盖已有私钥。收到新证书后先
校验公私钥匹配，再写入独立的 `identity-<uuid>` 目录，最后原子替换 `agent.env`。
旧身份文件保留，失败不会让已有证书配上一把新私钥。

自动升级的二进制替换失败时恢复原路径；旧版保留 `.prev`。这不等价于启动后的健康
自动回滚，后者仍需额外的运行时验收机制。

## API

- `GET /api/host-import/status`：是否配置凭据加密、是否开启 SSH 纳管。
- `POST /api/host-import/preview`：`{groupId,document}` → `{digest,hosts}`，hosts 不包含秘密。
- `POST /api/host-import/commit`：`{groupId,document,digest}` → `{assetIds}`，重新解析原文并
  检查摘要，单事务提交。摘要用于核对预览内容，不是授权凭证。
- `GET /api/host-import/credentials?groupId=…`：仅凭据元数据。
- `DELETE /api/host-import/credentials/{id}`：删除凭据，不卸载 Agent、不删除资产。
- `POST /api/host-import/credentials/{id}/enroll`：`{fingerprint}`，显式安装；成功响应
  `{status:"installed",message:…}`，不代表已在线。

前端入口：`web/src/components/ImportHostsModal.tsx`。
解析、加密及 SSH：`server/internal/hostimport/`；接口：`server/internal/api/hostimport.go`。
