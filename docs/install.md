# 安装

一台 Linux 服务器、一行命令。本文同时写给人和 AI agent：按顺序做，每一步都有可核对的结果。
从源码构建、高可用部署与全部配置项见 [部署与使用手册](deployment.md)、[高可用部署](../deploy/ha/README.md)。

## 1. 准备

| 项 | 要求 |
|---|---|
| 系统 | Linux，x86_64 或 arm64 |
| 资源 | 2 核 4 GB 内存、20 GB 磁盘起步；主机多、保留期长时加磁盘 |
| Docker | 24 以上，带 Compose v2（`docker compose version` 能输出版本）。没有就 `curl -fsSL https://get.docker.com \| sh` |
| 端口 | 80、443（控制台 HTTPS）、8081（agent / sensor 的 mTLS 接入），本机空闲且防火墙放行 |
| 地址 | 一个被纳管主机能访问到的域名或 IP，控制台与接入都用它 |

地址决定证书怎么来：

- **解析到公网 IP 的域名**：自动申请 Let's Encrypt 证书，浏览器与主机直接信任。要求公网能访问到这台机器的 80 与 443。
- **内网 IP 或内网域名**：用安装时生成的自建 CA。浏览器首次访问会提示不受信任；被纳管主机要先信任这张 CA（安装结束会打印命令与指纹）。

## 2. 安装

```bash
curl -fsSL https://github.com/yaklang/OpenXDR/releases/latest/download/install.sh | sudo sh -s -- <域名或 IP>
```

脚本依次：检查 Docker 与端口 → 下载编排文件到 `/opt/openxdr` → 生成数据库口令、admin 口令与凭据加密密钥（写进 `.env`，权限 600）→
签发 mTLS 证书（`certs/`）→ 写 Caddyfile → 拉镜像并启动 → 等 server 就绪 → 打印控制台地址、admin 口令与后续步骤。

可选环境变量（放在 `sudo` 后面，如 `sudo OPENXDR_DIR=/data/openxdr sh -s -- ...`）：

| 变量 | 默认 | 说明 |
|---|---|---|
| `OPENXDR_DIR` | `/opt/openxdr` | 安装目录 |
| `OPENXDR_VERSION` | 脚本所属版本 | 指定版本，如 `v0.1.0` |
| `OPENXDR_TLS` | 自动判断 | `acme` 强制申请 Let's Encrypt，`internal` 强制自建 CA |
| `OPENXDR_EMAIL` | 空 | Let's Encrypt 联系邮箱 |

## 3. 核对

```bash
cd /opt/openxdr
docker compose ps                     # nats、postgres、server、web、caddy 都是 running
curl -fsS https://<地址>/ -o /dev/null -w '%{http_code}\n'   # 自建 CA 时加 --cacert certs/ca.crt；应为 200
```

用 admin 与打印出的口令登录控制台。忘了口令：`grep ADMIN_PASSWORD /opt/openxdr/.env`（只在首次启动时生效，之后改口令请在控制台改）。

## 4. 接上 AI 与主机

1. **AI 模型**：控制台「系统设置 → AI 模型」填任意 OpenAI 兼容端点、模型名与密钥，保存后十几秒生效。不填也能用检测与降噪，只是没有 AI 研判与 AI 助手。
2. **信任 CA**（自建 CA 时）：在每台要纳管的主机上执行安装结束时打印的命令；命令先核对 SHA256 指纹，对得上才装进信任库，对不上会报错停下。
3. **添加主机**：「资产 → 添加主机」选组，复制安装命令到主机上执行（Linux root / Windows 管理员）。agent 安装包已内置在 server 镜像里，
   之后升级 OpenXDR，在线 agent 会自动跟着升级。

## 5. 升级、备份与卸载

- **升级**：再执行一遍安装命令（已有的口令、密钥与 CA 保留不动），或改 `.env` 里的 `OPENXDR_VERSION` 后
  `docker compose pull && docker compose up -d`。0.x 版本升级前看一眼 [CHANGELOG](../CHANGELOG.md)。
- **备份**：`.env`、`certs/` 与数据库（`docker compose exec -T postgres pg_dump -U openxdr openxdr > openxdr.sql`）。
  `HOST_CREDENTIAL_KEY` 丢了，库里加密的主机凭据与模型密钥就解不开。
- **卸载**：`cd /opt/openxdr && docker compose down -v`（`-v` 会删掉全部数据），再删目录。

## 6. 常见问题

| 现象 | 处理 |
|---|---|
| 端口被占用 | 停掉占用 80 / 443 / 8081 的服务，或换一台机器；OpenXDR 自己占用的不算 |
| Let's Encrypt 申请失败 | 确认域名解析到本机公网 IP、公网能访问 80 与 443；内网环境改用 `OPENXDR_TLS=internal` |
| 主机上执行安装命令报证书错误 | 自建 CA 模式下主机还没信任 CA，见第 4 步 |
| agent 连不上 | 主机到 `<地址>:8081` 的网络与防火墙；`docker compose logs server` 看拒绝原因 |
| 拉镜像慢或失败 | 给 Docker 配镜像加速或代理；镜像在 `ghcr.io/yaklang/` 下 |

## 给 AI agent 的说明

如果你是替用户安装 OpenXDR 的 AI agent，请：

1. 先只读地检查环境：系统与架构、`docker compose version`、80 / 443 / 8081 是否被占用、磁盘与内存。缺 Docker 时**先问用户**是否允许安装。
2. **问用户**控制台用哪个域名或 IP，并说明公网域名与内网地址在证书上的区别（见第 1 节）。不要自己猜一个地址。
3. 执行第 2 节的安装命令，完整保留输出。失败时按第 6 节排查，不要关闭防火墙、不要改与 OpenXDR 无关的系统配置。
4. 按第 3 节核对，全部通过后向用户报告：控制台地址、admin 口令、自建 CA 时被纳管主机要执行的信任命令与 SHA256 指纹，以及第 4 节的后续步骤。
5. `.env` 里除 admin 口令外的内容（数据库口令、`HOST_CREDENTIAL_KEY`）不要输出到对话里，提醒用户备份即可。

### 队列持久确认

安装脚本同时下载该 Release 的 `nats.conf`，编排将其只读挂载给 NATS。配置包含 4 MiB 消息上限与 `sync_interval: always`，保证发布确认前同步持久数据；手动安装也需下载同版本配置，不能退回只带 `--jetstream` 的默认启动方式。
