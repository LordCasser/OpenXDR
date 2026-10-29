# 跨宿主机高可用部署

该部署面向两个 PVE 故障域：`node1=10.1.1.198`、`node2=10.1.1.197`，入口 VIP
为 `10.1.1.199`。独立 witness 运行 etcd DCS 和第三个 JetStream 节点，只通过
mTLS 接受连接。任一 PVE 整机失联后，剩余 PostgreSQL 副本可晋升，JetStream
仍保有 2/3 quorum，VIP 漂移到存活节点。

组件边界：

- Patroni 管理两个 PostgreSQL 16 数据节点，同步复制降低自动切换的数据损失窗口；
- 每个应用节点的 HAProxy 在 `127.0.0.1:15432` 只转发 Patroni primary；
- 三节点 NATS JetStream 使用 mTLS route，应用仅访问本机 `127.0.0.1:4222`；
- Keepalived 以 `/readyz` 为依据持有 `10.1.1.199`；
- 两个 Prometheus 各自抓取两端 OpenXDR、Patroni 和本机 NATS exporter。

## 初始化

证书与 `.env` 不能提交。先生成 HA PKI，再分别渲染节点配置：

```bash
deploy/ha/generate-certs.sh runtime/pki <witness-address>
export OPENXDR_PASSWORD=... POSTGRES_PASSWORD=... REPLICATION_PASSWORD=...
export NATS_ROUTE_PASSWORD=... VRRP_PASSWORD=... ADMIN_PASSWORD=...
export GRAFANA_ADMIN_PASSWORD=...                 # VRRP 密码最多 8 字符
deploy/ha/render.py --node node1 --witness <witness-address>
sudo deploy/ha/prepare-runtime.sh runtime
docker compose -f docker-compose.ha-node.yml config --quiet
docker compose -f docker-compose.ha-node.yml up -d --build
```

`OPENXDR_PASSWORD` 与 `NATS_ROUTE_PASSWORD` 只允许 URL-safe 字符
`A-Z a-z 0-9 . _ ~ -`；`VRRP_PASSWORD` 只允许 1-8 位字母或数字。渲染器会拒绝
不安全值，避免 YAML、连接 URL 或 Keepalived 静默误解析。

节点 `runtime/secrets` 只放 HA CA、对应 NATS 证书和 etcd client 证书；
`runtime/app-certs` 放 agent gRPC 使用的原有 CA 及包含 VIP SAN 的 server 证书。
Witness 使用 [witness-compose.yml](witness-compose.yml) 和渲染后的
`witness-nats.conf`，只接收 `2379/tcp` 与 `6222/tcp`。如果 witness 上已有不能
重启的 Docker 工作负载，可安装固定版本的 etcd、NATS 二进制，并使用
[`systemd/`](systemd/) 中的受限服务单元；部署前按实际地址调整 etcd 的
`--advertise-client-urls`。公网端口即使有 mTLS，也应在上游防火墙限制来源地址。

`runtime/` 已被 Git 忽略。CA 私钥不能留在应用 VM；签发完成后应复制到至少两个
受控的离线备份位置，再从节点删除。应用节点只保留运行所需的叶子证书。

## 升级

用 [`release.sh`](release.sh) 从当前提交滚动发布：

```bash
SSH="ssh -F <ssh 配置>" GOPROXY=https://goproxy.cn,direct deploy/ha/release.sh <节点1> <节点2>
```

脚本在本地构建 server / web 镜像（标签为提交短哈希），连同 `rules/`、`tasks/` 推到节点，
先升不持有 VIP 的节点，`readyz` 通过后再升另一个；任一步失败立即停下。
每个节点切换前把旧镜像标成 `pre-<标签>`，回滚方式见脚本头部注释。
agent 不走这个脚本：把新版本放进节点的 `dist/` 目录，agent 重连时自动升级。

独立 DYGK 引擎的单节点配置、升级和恢复边界见 [dygk.md](dygk.md)。节点存在
`docker-compose.dygk.yml` 时，发布脚本自动合并它以保留 server 控制通道；不会自动
部署或升级引擎镜像，也不会把单实例引擎变成 HA。

时序规则（`temporal-rules/`）按内容哈希发布成节点上的不可变版本目录 `temporal-rules/v-<哈希>/`（带 `SHA256SUMS`），
再原子切换 `temporal-rules/current` 链接，保留最近 5 个版本；compose 只读挂载整个 `temporal-rules/` 到容器 `/temporal-rules`。
开启时在节点 `.env` 设 `TEMPORAL_RULES_PATH=/temporal-rules/current`，server 每 `RULES_RELOAD_SECONDS` 整批重载；
不设则保持单事件检测。回滚规则：把 `current` 链接切回旧版本目录（`ln -sfn v-<旧> current.tmp && mv -T current.tmp current`）。

## 业务日志

[持久日志与集中查询](logs/README.md) 使用 journald 和受限 SSH 归档，容器重建后仍可查询旧日志。
节点存在 `docker-compose.logs.yml` 时，滚动发布自动合并日志驱动配置。

Patroni 探测使用 `HEAD /primary`，保留主库 200、从库 503 判定，避免 GET 正文在探测端提前
关闭连接时产生重复的 ConnectionResetError。部署时先校验配置，再平滑重载 HAProxy。

## 备份与恢复

节点外逻辑备份、隔离恢复验收和容量处理顺序见 [backup-recovery.md](backup-recovery.md)。
同步副本不能替代独立备份，切换演练也不能替代恢复验收。

## 验收

1. `patronictl list` 必须是一主一同步副本；
2. JetStream stream 必须 `replicas=3` 且三个 peer current；
3. `curl http://10.1.1.199:8080/readyz` 与实际 agent 上报均成功；
4. 依次停止 node1、node2（一次只停一个），确认 VIP 漂移、PostgreSQL 晋升、事件持续增长；
5. 恢复节点后确认 Patroni 自动追平、JetStream replica current、Prometheus targets 全绿。

本环境在 2026-08-10 完成两轮整机切换：关闭 node2 后 node1 晋升到 timeline 5；
关闭 node1 后 node2 晋升到 timeline 6。两轮均保持 JetStream quorum 且事件计数
持续增长。Keepalived 的实测入口恢复窗口约 30 秒，因此客户端必须重连，不能把它
描述为零中断。

这套架构容忍一个 PVE 故障，不容忍 PVE 与独立 witness 同时故障。Witness 不保存
PostgreSQL 业务数据，但第三个 JetStream replica 会保存加密传输后的事件队列副本。
