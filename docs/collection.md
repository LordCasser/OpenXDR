# 采集端详解

本文是 agent（端点采集）与 sensor（全流量探针）的完整参考，内容逐一对照代码核实，
每条结论标注源码位置。事件字段的完整 schema 见 [events.md](events.md)，
syslog 接入的服务端行为见 [detection.md](detection.md)。

## 总览：三条数据源

| 数据源 | 部署位置 | 产出 | 传输 |
|---|---|---|---|
| agent（Rust） | 每台被监控主机（Linux / Windows） | 进程（启动+退出）、文件、认证、网络（TCP 出入站、UDP 出站）、DNS、注册表等事件 | gRPC 双向流 :8081 |
| sensor（Rust） | 核心交换机镜像口（仅 Linux） | 会话元数据（DNS 查询/应答、TLS SNI/JA3/JA3S/证书元数据、HTTP），不存 PCAP | gRPC 客户端流 :8081 |
| syslog | 任意网络设备/主机 | 非结构化日志 | UDP+TCP 同端口（默认不启用） |

agent 事件的 OCSF 归一化在 **agent 侧**完成（raw_json 已是 OCSF 风格 JSON，
server 原样落库）；sensor 与 syslog 的归一化在 **server 侧**完成。

## agent 通用机制

### 注册与配置下发

- 启动参数：**无命令行参数**，全部走环境变量（`agent/src/main.rs`）：
  - `OPENXDR_SERVER`：server 地址，默认 `http://127.0.0.1:8081`（`main.rs:17`）
  - `OPENXDR_CA` / `OPENXDR_CERT` / `OPENXDR_KEY`：mTLS 三件套，必须同时配置；
    全不配=明文，配一半=报错（`agent/src/tls.rs:10-26`）
- 注册时上报 hostname、os、非回环 IP 列表、版本（`main.rs:31-36`）
- 采集配置由 server 在 `Register` 响应的 `config_json` 下发（`main.rs:39`）。
  **无热更新通道**：agent 断线固定 5 秒重连并重新注册（`main.rs:21-23`），
  配置随重注册生效
- 配置解析失败或为空一律回退内置默认（`collector/config.rs:34-46`）——
  让 agent 变瞎比配置不生效严重得多

### 事件出口（EventSink）

上报侧堵塞时**丢弃并计数**（`dropped_events` 字段携带累计值），绝不反压采集——
阻塞采集只会让内核缓冲区溢出，丢得更多且无从知晓
（`collector/mod.rs:123-144`）。channel 容量 1024。

### 进程血缘注册表（ProcessRegistry）

- pid → UUID v4 GUID 映射，父 GUID 由 ppid 查表得到；父早于 agent 启动则为空
  （`collector/registry.rs:24-38`）
- 进程退出即删除登记，表里正常只有存活进程；漏掉退出事件的条目超过 65536 条时
  按序号淘汰最旧一半。早先只靠淘汰，宿主机每天几十万次 exec，两小时就把早于 agent
  启动的长驻服务挤出表，之后它们的网络连接有三分之一挂不回进程（`registry.rs`）
- 每条登记还记着启动时间与所在容器：退出事件据此给出运行时长与容器，
  网络与 DNS 事件按 pid 取到同一份容器信息
- pid 复用语义：新登记直接覆盖旧条目（`registry.rs:30-31`）
- 启动时用 /proc（Linux）或 sysinfo（Windows）快照 seed 预登记现有进程
  （`collector/mod.rs`、`windows.rs` `seeded_registry`）
- **退出事件复用启动时的 GUID**：Terminate 分支优先 `guid_of(pid)` 查已有映射，
  退出与启动事件共享 `process_guid`，血缘不断（`mod.rs:230-251`）

### exe SHA-256

- 各进程采集路径共用 `process_event()` 组装，哈希在此统一计算
  （`collector/mod.rs:233` 起）
- 实现：文件可读且 ≤128MB 才算；缓存键 (path, mtime, size)，上限 4096 条，
  满则整体清空（`collector/hash.rs:20-46`）
- Windows ETW 的 ImageName 先经设备路径→Win32 路径转换再进哈希
  （`collector/windows.rs:95` `to_win32_path`），否则按设备路径读文件必失败

## Linux 采集路径

### 进程采集三级降级

```
--features ebpf 构建：  eBPF tracepoint → netlink proc connector → 轮询
默认构建：              netlink proc connector → 轮询
```

| 路径 | 机制 | 前提 | 证据 |
|---|---|---|---|
| eBPF | tracepoint `sched_process_exec`（启动）+ `sched_process_exit`（退出），内核直接给路径 | `--features ebpf` + root | `collector/linux.rs`、`agent/ebpf/src/main.rs` |
| netlink | proc connector，订阅 `PROC_EVENT_FORK`/`EXEC`/`EXIT`；fork 仅用于血缘登记不上报 | CAP_NET_ADMIN + 初始 pid 命名空间 | `collector/netlink.rs:20-24` |
| 轮询 | 每秒进程表快照 diff，新 pid 报启动、消失 pid 报退出 | 无 | `collector/poll.rs` |

关键行为：

- **逐级降级不跳档**：eBPF 启动失败先试 netlink，netlink 不可用才退轮询
  （`linux.rs:39-51`），与默认构建同一条链
- **命名空间检测**：netlink 启动前检查 `/proc/self/ns/pid` inode 是否为初始
  pid ns（4026531836），容器/WSL2 中直接拒绝启动并回落轮询——宁可弱采集
  也不产假数据（`netlink.rs:32-58`）。eBPF 路径**无**此检测
- **短命进程**：eBPF/netlink 在事件路径上从 /proc 补全 cmdline/ppid，进程已退场
  就只报 pid、字段留空，事件本身不丢（`linux.rs`、`netlink.rs:148-167`）；
  轮询路径明确会漏 1 秒内启动又退出的进程（`poll.rs`），且 WSL2 实测
  捕到的短命进程多为空 cmdline"鬼影"（扫描间隔内进程已退场，/proc 读不到）——
  轮询兜底下进程类规则基本无法命中，这是环境性降级，不是规则问题
- **进程退出事件**（activity_id=2 Terminate）：netlink 解析 `PROC_EVENT_EXIT`
  （含 exit_code，`netlink.rs:24,139`）；轮询 diff 消失的 pid；eBPF 挂
  `sched_process_exit`，退出码由 `syscalls:sys_enter_exit_group` 记下（取低 8 位，与 `$?` 一致；
  被信号杀掉的进程不走 exit_group，退出码为空；内核没开 syscall tracepoint 时只降级这一项）。
  退出事件复用启动时的进程 GUID（见上节），并带 `process.created_time` 与 `duration_ms`
- **进程名**：内核的 comm 最多 15 字节，截断名是可执行文件名前缀时换回完整文件名
  （`ip6tables-resto` → `ip6tables-restore`）
- **容器归属**（`container.rs`）：按 `/proc/<pid>/cgroup` 认出 docker / podman / containerd / cri-o 容器、
  Proxmox 的 LXC 容器（`/lxc/<VMID>`、`lxc.payload.<VMID>`）与 QEMU 虚拟机进程（`qemu.slice/<VMID>.scope`）、
  systemd-nspawn，事件里写成 `container: {runtime, uid, name}`。名字读 docker 容器配置与
  `/etc/pve/lxc|qemu-server/<VMID>.conf`，读不到只给 ID。agent 必须跑在宿主机的 cgroup 命名空间里
  （systemd 服务即是；放进容器跑要 `--cgroupns=host`），否则看到的是相对路径
- **username**：eBPF/netlink 路径从 `/proc/<pid>/status` 读 real uid，
  再查 `/etc/passwd` 解析成用户名（结果带缓存）；passwd 查不到退化为
  uid 数字串，与轮询路径一致（`mod.rs:185` `username_of`）

### 敏感文件监控（fswatch：fanotify 优先，inotify 兜底）

- **fanotify 路径**（有 CAP_SYS_ADMIN 时）：FID 模式
  （`FAN_REPORT_FID|FAN_REPORT_DIR_FID|FAN_REPORT_NAME`）递归打标，
  覆盖建/删/改/移动；**事件自带 pid**——读 `/proc/<pid>/exe`、`/proc/<pid>/comm`
  与 `username_of(pid)`，文件事件带进程上下文（"谁改的"）。路径经
  mountinfo + `open_by_handle_at` 解析（`fswatch.rs:70` `spawn`）。
  两个实机勘定（2026-08-09 WSL2 回放）：挂载 fd 必须 O_RDONLY 打开
  （O_PATH 在 WSL2 6.18 内核下 open_by_handle_at 一律 EBADF，
  `fswatch.rs` `mount_fd_for`）；建/删/移动事件内核发的是
  DFID/DFID_NAME 信息记录（父目录句柄+目录项名），与 FID 同布局，
  `fa_parse` 三种类型统一解析
- **inotify 路径**（fanotify 不可用时干净回落）：启动时递归 add_watch
  （限深 `MAX_DEPTH=4`，防大目录 watch 爆炸），运行中 `IN_CREATE|IN_ISDIR`
  动态补挂新子目录；无进程上下文（inotify 不提供）（`fswatch.rs:31,164`）
- 两条路径产出格式一致：class_uid=1001，activity_id 增 1/删 4/改 3，
  `file.path`；fanotify 路径额外带 `process.*` 与 `username`
- 默认目录（`fswatch.rs:93` `default_targets`）：`/etc`、`/etc/cron.d`、
  `/etc/cron.daily`、`/etc/sudoers.d`、`/etc/ssh`、`/root/.ssh`、
  `/etc/systemd/system`、`/var/spool/cron`、`/var/spool/at`，以及启动时枚举
  `/home` 一层补进各用户 `.ssh`。server 下发 `fileWatchDirs` 非空时
  **整体覆盖**默认清单
- **单文件目标**：除目录外还支持盯单个文件——用户 shell rc
  （`/etc/profile`、`/etc/bash.bashrc` + /root 与 /home 各用户存在的
  `.bashrc`/`.bash_profile`/`.profile`，T1546.004）。inotify 用
  `IN_DELETE_SELF/IN_MOVE_SELF` 系掩码，fanotify 不带目录专属标记；
  已被目录 watch 覆盖的文件自动去重，不会双报
- 启动日志标明实际走哪条路：`fanotify 递归盯 N 个目录（含进程上下文）` 或
  `fanotify 不可用（原因），回落 inotify 递归监控`

### 登录事件（authwatch，wtmp/btmp）

- 每 5 秒轮询 `/var/log/wtmp`（成功）与 `/var/log/btmp`（失败）
  （`authwatch.rs:17,35-46`）
- 增量：启动 offset 置为文件末尾（历史不重放），之后按 384 字节完整记录消费，
  残缺尾部留到下一轮；logrotate 截断时 offset 归零重读（`authwatch.rs:47-91`）
- 只收 `ut_type==USER_PROCESS(7)` 且用户名非空的记录；登出跳过
  （`authwatch.rs:100-113`）
- 成功/失败完全靠**文件名**区分（btmp→`status_id:2`），记录本身无失败标志
  （`authwatch.rs:29-31,124`）
- 字段：`user.name`、`src_endpoint.ip`（ut_host）、`service.name`（ut_line）
  （`authwatch.rs:105-128`）

### 网络采集（netwatch，仅 eBPF 构建）

- **TCP 出站**：tracepoint `sock:inet_sock_set_state` 在 `SYN_SENT` 记下发起进程，
  到 `ESTABLISHED`/`CLOSE` 拿到真实源端口再上报（`agent/ebpf/src/main.rs`）
- **TCP 入站**：同一 tracepoint 上子套接字 `SYN_RECV → ESTABLISHED` 即一条建立成功的入站。
  握手在软中断里完成没有进程上下文；tracepoint 也不分网络命名空间。目的是宿主机自己的地址时，用户态按本机端口
  查监听表找服务进程（查不到才重扫，每秒最多一次）；目的是容器地址的（LXC 有自己的地址）不查——按端口会错归到
  宿主机上同端口的进程——只按 `/etc/pve/lxc/*.conf` 里的静态地址认出是哪个容器
- **UDP 出站**：kprobe `udp_sendmsg` / `udpv6_sendmsg`，目标优先取 `msg_name`（未连接套接字的 sendto），
  否则取套接字上 connect 的对端；内核里按 (进程, 目标) 60 秒采样（LRU 8192），源端口 53 的回包直接丢弃。
  用户态再丢掉从本机 UDP 服务端口发出的回包（NTP、syslog、corosync 之类），以及组播、广播。
  目的端口 53 的发送不成网络事件，只记「源端口 → 进程」给 DNS 采集归属（见下节）
- 用户侧丢 loopback；按 (对端IP, 端口) 60 秒去重，出站 / 入站 / UDP 各一张表，表满 4096 清过期
- 带 pid → 进程 GUID 与容器，网络事件直接挂进血缘；`connection_info.direction` 区分 inbound / outbound，
  `conn_tuple` 与 sensor 同格式（发起方在前，`tcp:` / `udp:` 前缀），横向移动关联与网络规则零改动复用
- 出站目的地址最近被本机解析过的，带上 `dst_endpoint.hostname`（DNS 采集的应答缓存，按 TTL 记 1 分钟～1 小时）
- 默认构建（netlink 模式）**无网络连接采集**——proc connector 没有网络事件；DNS 采集不依赖 eBPF，照常工作

### DNS 采集（dnswatch，Linux）

- AF_PACKET 抓本机经过的报文，经典 BPF 过滤器在内核里只放行 UDP 53（IPv4 不收分片，IPv6 不看扩展头），
  用户态不碰别的包。按 (客户端, 源端口, 事务 ID) 配对查询与应答，同一报文在 veth / 网桥 / 物理口 / lo
  各抓到一份只算一次；应答到了再等 1 秒上报（等 eBPF 的进程归属就位），5 秒没应答按无应答上报
- 只收本机自己（客户端地址是本机地址）与本机容器当客户端的查询：veth 上只认容器发出的查询、送回容器的应答。
  网桥上转发的虚拟机流量、别的主机来问本机或容器里 DNS 服务（比如跑在 LXC 里的 AdGuard）的查询都不收。
  Proxmox LXC 的接口名 `veth<VMID>i<n>` 直接认出容器
- 容器是解析器时，它发出的上游查询其实是替局域网客户端问的：送进容器的客户端查询只记不报，容器 5 秒内转发同名同类型的查询时，
  事件带上 `requester.ip`（真正问的客户端），研判与抑制按它区分，告警不再全算在解析器头上
- 发起进程按源端口取 eBPF UDP 事件记下的进程；默认构建只有地址没有进程
- 同一 (客户端, 域名, 类型) 60 秒内只报一次；应答里的 A / AAAA 地址进缓存，给出站连接回填域名
- 事件字段与 sensor 的 DNS 事件同一约定（`query.hostname`、`answers[].ip`），DNS 规则与情报域名碰撞对两路一视同仁

### 内核模块监控（kmodwatch）

- 每 30s 读 /proc/modules 做 diff：新模块报加载（class_uid=1005，
  activity_id=1）、消失报卸载（4）；首轮基线静默（`kmodwatch.rs`）
- 路径按 /lib/modules/$(uname -r)/ 解析，解析失败只报名字不编造路径；
  /proc/modules 拿不到加载者——进程与 username 留空（那是 audit/eBPF 的领域）

### 设备清单（inventory，监听端口与云环境）

`inventory_linux.rs` 读 `/proc/net/{tcp,tcp6,udp,udp6}`：TCP 取 LISTEN，UDP 取未连接且端口低于
`ip_local_port_range` 下界的套接字。属主按 socket inode 扫 `/proc/<pid>/fd` 找，只在监听集合
变化时重扫。只看得到 agent 所在网络命名空间。云环境由 `cloud.rs` 在进程启动时探测一次
（手写最小 HTTP 客户端，连接 300ms、读写 1s 超时）：AWS 要求实例 ID 格式正确且拿得到
region（排除 OpenStack 的 EC2 兼容接口），其余厂商各自校验实例 ID 前缀，拿不准就不报。
系统显示名由 `osinfo.rs` 按进程识别一次：Linux 读 os-release 的 `PRETTY_NAME`（麒麟、
统信等国产发行版同规范，解析是纯函数、CI 可测），Windows 读注册表；拿不到就不带该键。
产出 class 5001，见 [事件模型](events.md#5001-设备清单)。

## Windows 采集路径

### 进程采集（ETW）

- 订阅 `Microsoft-Windows-Kernel-Process`（GUID `22fb2cd6-...`），
  处理 **event ID 1（启动）与 2（停止）**（`windows.rs:19,30`）。
  Stop 事件产 Terminate（activity_id=2），pid + ImageName（转 Win32 路径），
  cmdline/username 留空（进程已退场，句柄多半开不到）
- ETW 事件本身只有 pid/ppid/ImageName；cmdline 与 username 现场补
  （`OpenProcessToken`→`LookupAccountSidW` 得 `DOMAIN\user`）
- cmdline 补全双路径：`NtQueryInformationProcess(ProcessCommandLineInformation)`
  （Win 8.1+）；失败时回落 **PEB 读取**（ProcessBasicInformation 拿 PEB 地址 →
  ReadProcessMemory 读 RTL_USER_PROCESS_PARAMETERS → CommandLine），
  **Win7/2008R2 由此获得命令行**（`windows.rs:235` `command_line_peb`）
- ImageName 常是设备路径（`\Device\HarddiskVolumeN\...`），直接用会让
  exe SHA-256 落空；采集时经 `QueryDosDeviceW` 映射翻成 Win32 路径
  （`windows.rs:95` `to_win32_path`）
- 需要管理员权限；失败回落**轮询**（`windows.rs:5`）。轮询路径下
  username 是 SID 字符串而非用户名（`poll.rs`）

### 网络采集（netwatch_win，ETW Kernel-Network）

- 订阅 `Microsoft-Windows-Kernel-Network`（GUID `7dd42a49-...`），只取
  **event ID 12（TcpConnect）**——本机主动 connect 才触发；端口字段是网络
  字节序，已换算（`netwatch_win.rs`，实机勘定）
- 归一化与 Linux eBPF 路径完全同构：共用 `netwatch::conn_event` 组装
  （class_uid=4001、conn_tuple 同格式、60s 同目标采样去重、loopback/
  未指定地址不报）；UDP 不做（该 provider 的 UDP 只有逐报文事件，无连接语义）
- **与进程采集共享同一张 GUID 注册表**——网络事件的 process_guid 与进程
  血缘严格一致（`mod.rs` 把 Arc<Mutex<ProcessRegistry>> 同时交给
  netwatch_win 与 windows::run）
- 独立 trace session，订阅失败只打日志降级，不影响进程采集主路

### 持久化点快照（persistwatch）

七类持久化点，30 秒一轮快照 diff，各自独立基线、首轮静默、单类读取失败
只跳过自己这一轮（`persistwatch.rs`）：

| 监控对象 | 事件类别 | 说明 |
|---|---|---|
| 注册表 Run/RunOnce/Winlogon（HKLM+HKCU） | 201002 | 增(1)/改(3)/删(4)，删除带旧值内容 |
| Startup 目录（全局+每用户） | 1001 | 增(1)/删(4)，修改不报 |
| **Windows 服务**（`HKLM\SYSTEM\CurrentControlSet\Services`） | 201002 | `services_snapshot`：ImagePath+启动类型+**运行状态**（SCM 枚举，EventLog 等安全服务被停止产生 Modify；枚举失败整轮跳过防误报） |
| **计划任务**（`C:\Windows\System32\Tasks` 递归） | 1001 | `tasks_snapshot`：快照 路径→(mtime,size)，增/改/删全报 |
| **Defender Exclusions / AppInit_DLLs / IFEO Debugger / HKCU CLSID** | 201002 | `WATCH_TREES` 递归枚举（键不存在静默跳过）：T1562.001 排除项篡改、T1546.010/012、T1546.015 COM 劫持 |
| **WMI 事件订阅**（`root\subscription` 的 __EventFilter/__EventConsumer） | 1001 | powershell 子进程查询快照（30s），file.path 用 `wmi:...` 伪路径；T1546.003 |

- 事件无进程上下文（快照 diff 不知道谁写的），设计上不用注册表通知
  （`persistwatch.rs:3-6`）
- 非 REG_SZ/REG_EXPAND_SZ 的注册表值记为 `<type N, M bytes>` 占位

### 文件监控（fswatch_win，ReadDirectoryChangesW）

- 每个监控目录一个线程：`CreateFileW`（`FILE_FLAG_BACKUP_SEMANTICS`）打开目录，
  循环阻塞 `ReadDirectoryChangesW`，不递归（`fswatch_win.rs:46`）
- 事件映射：Added/RenamedNew→1、Removed/RenamedOld→4、Modified→3
  （改名天然拆成删+增两条）（`fswatch_win.rs:160` `rdcw_activity`）
- 默认目录：`C:\Windows\System32\drivers\etc`、`C:\Windows\System32\config`；
  `fileWatchDirs` 下发非空时覆盖；失败目录静默跳过
- 缓冲溢出（`ERROR_NOTIFY_ENUM_DIR`）打日志继续；事件格式与 Linux 侧完全一致
  （1001 + activity_id + `file.path`，无进程上下文——RDCW 不提供）

### 设备清单（inventory_win）

`GetExtendedTcpTable`（`TCP_TABLE_OWNER_PID_LISTENER`）与 `GetExtendedUdpTable`
（`UDP_TABLE_OWNER_PID`）取 v4/v6 监听表，UDP 端口 ≥ 49152 视为客户端套接字丢弃；
进程名与路径按 pid 补齐。云探测与 Linux 共用 `cloud.rs`。未实机验证。

### 登录与安全日志事件（authwatch_win）

- `EvtSubscribe` 订阅 Security 日志，只订未来事件：
  **4624/4625**（登录成功/失败）、**4720/4726**（创建/删除用户）、
  **4732**（成员加入本地组）、**1102**（Security 日志被清空）、
  **4648**（显式凭据登录）、**4719**（审计策略变更），统一归一化成 OCSF 3002
- 4624/4625 过滤：机器账号（`$` 结尾）、SYSTEM、空用户丢弃；成功事件额外丢弃
  LogonType 0/5；失败事件保留所有类型
- 4624/4625 解析字段：`TargetUserName`、`LogonType`、`IpAddress`、`Status`、
  `SubStatus`——后两个有值才写成 `status_code`/`status_detail`
  （4625 可区分"密码错"0xC000006A 与"账号锁定"0xC0000234 等）
- 新事件类型用平台自定义 `activity_id`（OCSF 3002 未定义，从 10 起）：
  10=创建用户、11=删除用户、12=加入本地组（组名在 `group_name`，
  是否管理员组由规则判定）、13=日志清空（另带 `log_cleared: true` 显式标记）、
  14=显式凭据登录、15=审计策略变更；机器账号同样过滤
- 另订阅 `Microsoft-Windows-PowerShell/Operational` 的 **4104**（Script Block
  Logging），归一化成 OCSF 1007 进程事件：`process.name=powershell.exe`、
  pid 取事件 Execution ProcessID、脚本体放 `process.cmd_line`（Sigma 的
  CommandLine 匹配因此直接作用于脚本内容）。分片不拼接：单片直接发，
  分片各发一条并标注 `message_number`/`message_total`。4104 依赖组策略开启，
  订阅失败只打日志，不影响 Security 主路
- 需要管理员或 Event Log Readers 权限；订阅失败只告警不影响其他采集

## 采集配置开关全表

配置存于资产上，随 Register 下发（`collector/config.rs:10-28`）：

| 开关 | 默认 | Linux | Windows |
|---|---|---|---|
| `collectFiles` | true | 控制 fswatch | 控制 fswatch_win |
| `collectAuth` | true | 控制 authwatch | 控制 authwatch_win |
| `collectPersist` | true | 无消费者 | 控制 persistwatch |
| `collectNetwork` | true | 控制 DNS 采集；网络连接仅 eBPF 构建有 | 控制 netwatch_win |
| `collectInventory` | true | 控制 inventory | 控制 inventory_win |
| `collapsePeriodic` | true | 周期行为折叠（见下） | 同左 |
| `fileWatchDirs` | []（内置清单） | 覆盖 fswatch 默认目录 | 覆盖 fswatch_win 默认目录 |
| （进程采集） | — | 无开关，按降级链选择 | 无开关，无条件启动 |

### 周期行为折叠

宿主机上大量进程事件来自周期性的守护与监控：PVE 防火墙每几秒导出规则、状态守护进程轮询存储、
监控面板经 SSH 每隔几秒跑一遍 `ps`。生产两台 PVE 上这类进程占了一半以上的事件。所有进程采集路径
（eBPF、netlink、ETW、轮询）都经 `collector::emit_process` 出口，在这里折叠（`collector/periodic.rs`）：

- **认定**：键是「父进程路径 + 父命令行 + 子进程路径 + 子命令行」，10 分钟窗口内出现 20 次以上即认定为周期行为
- **折叠**：之后这个键的启动与退出不再逐条上报，每 10 分钟报一条汇总（OCSF 1007，`activity_id` 99，
  `periodic.count` 与首末时间，进程与父进程字段照常，规则按进程字段判断时汇总事件一样能命中）；
  一小时没再出现的键忘掉，再出现重新逐条上报
- **从不折叠**：父进程未知的进程、平台指令拉起的进程树（server 要逐条核对指令归属）
- **血缘不丢**：被折叠进程的启动事件压在注册表里。它一旦拉起不是周期行为的子进程，或发起网络连接、
  DNS 查询，压着的启动事件（连同被折叠的祖先）先补发，事件保留原本的启动时间，server 按 GUID 串血缘

关掉 `collapsePeriodic` 即恢复逐条上报。

## sensor（全流量探针，仅 Linux）

### 抓包后端

| 后端 | 机制 | 前提 | 证据 |
|---|---|---|---|
| `afpacket`（默认） | AF_PACKET v3 mmap 零拷贝环（2MiB×64 块），`PACKET_FANOUT_HASH` 按流哈希多 worker，内核重组分片 | 任意 Linux | `capture/afpacket.rs:12-19,81-89,150-158` |
| `afxdp` | XDP 程序按 rx_queue redirect 到 XSKMAP，**仅入向（RX）** | `--features xdp` + 驱动支持 | `capture/afxdp.rs:19,185`、`sensor/ebpf/src/main.rs:19-24` |

- `SENSOR_BACKEND` 选择后端，`SENSOR_WORKERS` 决定并行度（afxdp 下
  worker 号=网卡队列号）（`main.rs:48,114-117`）
- mTLS 变量与 agent 相同（`OPENXDR_CA/CERT/KEY`，`sensor/src/tls.rs:14-26`）

### 协议解析（按方向各探测一次）

| 协议 | 触发 | 提取字段 | 不解析 |
|---|---|---|---|
| DNS | sport/dport=53，按报文 QR 位区分查询/应答 | 查询名、**rcode、A/AAAA 应答 IP（至多 4 个）**；域名解析支持 RFC 1035 压缩指针（限跳 16 次防循环，越界即畸形） | TXT 等其他记录类型 |
| TLS | record 0x16；ClientHello（0x01）与 ServerHello（0x02）**各探一次** | SNI、JA3（客户端）、**JA3S（服务端）**，均为 md5 且 GREASE 按 RFC 8701 剔除；**证书元数据**：叶证书 subject/issuer CN、自签标志（subject/issuer 原始 DER 相等的启发式，非签名验证）、有效期（unix 秒） | TLS 1.3 证书（加密传输，协议上不可见）、证书链与签名验证 |
| HTTP | HTTP/1.x 请求行（9 种方法白名单） | URI、Host、User-Agent（首包前 4KB，无跨包重组） | 方法/状态码不进上报结构 |

TLS 证书跨 TCP 分段是常态（叶证书+链一般 1.5–4KB），服务端方向做**有界重组**：
每条流一个握手缓冲（上限 16KB），按 record → handshake 增量解析，不完整等下一个包；
ServerHello 扩展 supported_versions=0x0304 判定 TLS 1.3 后立即停止等证书，
看到应用数据 record（0x17）或缓冲超限同样停止。X.509 解析是自研迷你 DER walker
（`sensor/src/x509.rs`），不引新 crate，畸形一律返回 None。

证据：`sensor/src/proto_id.rs`（`read_name`、`parse_dns_response`、`parse_server_hello`、
握手重组与 Certificate 提取）、`sensor/src/x509.rs`（DER/有效期/CN 解析）。
其他协议（SSH/SMTP/ICMP 等）无实现。
DNS/JA3S/证书字段经 proto `FlowRecord` 的 `dns_rcode=19` / `dns_answers=20` /
`ja3s=21` / `tls_cert_*=22-26` 上报（`proto/sensor.proto`）。

### 流聚合与上报

- 五元组"小端在前"归一化，双向并入同一条流；方向判定：纯 SYN 发送方为客户端，
  SYN+ACK 为服务端，UDP/中途观察以首包发送方为客户端（`flow.rs:21-43,136-142`）
- 逐方向累计包数/字节数、TCP 标志位并集（`flow.rs:159-167`）
- 导出条件：TCP 见 FIN/RST、空闲 30s、最长生存 300s；每 5s 扫描；
  每 worker 上限 100 万条流（`flow.rs:101-110,173-191`）
- **无采样、无逐事件去重**——聚合本身就是"五元组归并成会话"
- 上报攒批：满 256 条或 2 秒一批，断线 5s 重连（`report.rs:12-13,92-117`）；
  上报队列（65536）满丢会话并计数；内核丢包经 `PACKET_STATISTICS` 统计上报
- server 侧归一化与 class_uid 判定（4001/4003）见 [events.md](events.md)

## 响应面（与采集同进程）

agent 的 `respond/` 模块执行 server 下发的指令：结束进程、主机隔离
（Linux nftables 独立表 / Windows WFP 独立子层）、封锁网络（nftables `openxdr_block` / Windows 防火墙规则组）、
隔离与恢复文件、锁定与解锁本机账号，以及平台 exec。指令一律真执行，闸门：
`RESPONSE_ENABLED` 全局开关、未配置 `ISOLATION_ALLOW` 拒绝隔离。
详见 [detection.md](detection.md) 响应处置一节。

## 采集状态快照

新版 Agent 使用独立的 ReportHealth RPC 上报缓存与采集路径状态，不把状态塞进积压的事件流。资产详情每 15 秒刷新，超过 90 秒未收到状态会显示历史快照；旧 Agent 没有快照时显示未知。
状态的 active 表示路径启动成功，degraded 表示已知降级，unavailable 表示当前不可用，disabled 表示配置关闭，unknown 表示尚无反馈。
状态覆盖进程、文件、网络、DNS、登录认证、监听端口清单、Linux 内核模块和 Windows PowerShell 订阅的主要路径；尚未反馈的路径保持 unknown，不能据此宣称整机采集完整。Windows 日志订阅启动成功不代表对应审计或 Script Block Logging 策略已启用。
监听端口或内核模块清单读取失败时保留上次有效基线，跳过本次差异事件并上报 unavailable；恢复后与有效基线比较，不能将读取失败解释为服务消失或模块卸载。Linux 登录认证按 wtmp/btmp 可读性及 journalctl 存活状态报告 active/degraded/unavailable。
队列丢失数仅覆盖本次进程运行期间的内存出口溢出，跨配置切换累计；不统计内核缓冲丢失与尚未刷盘数据。
上报时间偏差超过 5 分钟会拒绝保存，应先校准 Agent 时钟。服务端保存接收时间，拒绝旧序号覆盖新状态，并继续按组限制读取。

### 缓存损坏与身份变化

缓存目录里认不出的文件、校验失败的批次、读不通的注册配置，以及运行中损坏的最老批次，都移入 `quarantine/`
（文件名前加毫秒时间戳）后继续运行，不拒绝启动、补传也不会卡在坏批次上；只有锁、权限这类环境错误才退出（`spool.rs`）。
server 返回的注册身份和缓存里的不同（server 重装、数据库重建）时，旧身份的批次与注册配置移入隔离区，agent 退出一次，
由服务管理器以新身份拉起，不陷入重启循环。

单条超过 3 MiB 的事件丢弃并计入丢失数，不让 agent 退出；进程事件的命令行在采集侧截到 32 KiB
（argv 在 `ulimit -s unlimited` 下能到几 MB）。缓存积压超过 16 批时（离线或 server 慢）改为 30 秒或满 500 条落一批，
在线时仍每秒或满 128 条一批：8192 个批次文件的上限因此能覆盖几十小时离线，而不是约 2 小时就先于字节上限撞满。

### 停止与升级

Agent 收到 Linux SIGTERM/SIGINT 或 Windows Ctrl+C/Ctrl+Break 后，关闭采集入口并最多等待 30 秒将已接收事件写入本地缓存；连接可用时继续补传释放缓存空间。落盘完成即可退出，尚未确认的磁盘批次在重启后补传。失败或超时会明确记录内存事件可能丢失并以非零状态退出。

自动升级校验注册身份后才执行；替换成功后同样先排空再退出。升级下载最多等待 120 秒，新程序 `version` 自检最多等待 10 秒。服务管理器的停止宽限期应大于 30 秒；SIGKILL、强制结束计划任务和断电不经过该流程，仍可能丢失未落盘事件。Windows 服务管理器停止事件未接入此控制台信号路径，不应将强制停止视为已排空。

### Linux 登录文件有界追踪

wtmp/btmp 每次轮询最多读取 1024 条 384 字节记录（约 384 KiB），积压在后续五秒轮询继续读取，
不按文件增长量一次分配内存。末尾不足一条的字节不前移游标，等记录完整后解析。启动游标对齐完整记录边界。
记录文件设备号与 inode；即使替换文件大小相同或更大，也从新文件开头读取；当前 inode 变短时从头读取。
这是当前路径轮询，不保留已轮转旧文件句柄：旧文件尚未读完就被替换的尾部仍可能丢失，
同 inode 的 copytruncate 在两轮之间缩短后又增长到原大小也不能可靠识别。没有持久化登录文件游标，重启仍从当前末尾开始。
本地临时文件测试覆盖有界分批、同尺寸 inode 替换、普通截断与半记录追加，不等于生产日志轮转无损验收。

SSH journal 文本每行最多保留 16 KiB。超长或非 UTF-8 行整体拒绝，超长行排到换行后再读取下一条，
不能用截断前缀生成认证事件；拒绝数按 1、2、4 等次数输出累计日志，不打印原始日志内容。
当前拒绝计数仅在本轮 reader 内及 Agent 日志中，不是持久健康指标；排空无换行的流仍可能阻塞该 reader，
并未新增 journal cursor 或退出自动重启机制。

缓存对象析构时显式解锁，再关闭文件；避免并发创建子进程时临时继承的文件描述使正常关闭后的立即重开仍被锁阻塞。
回归测试保留复制句柄跨越对象关闭，再检查重新取得的独占锁没有被旧句柄关闭破坏。
