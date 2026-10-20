# 实验性时序规则

此目录独立于单事件 `rules/`，默认不启用。配置 `TEMPORAL_RULES_PATH` 指向本目录才能加载，
容器需要只读挂载；同时保持 `RULES_PATH` 指向配套基础规则。基础规则和时序规则必须成套发布。

规则字段见 [时序检测实现约定](../docs/temporal-detection.md#规则格式)，`group_by` 可选 `asset`（默认）或 `account`，未知取值拒绝加载。
生产按不可变版本目录发布时，每个版本目录需带 `SHA256SUMS`，见同文档「不可变版本目录发布」。

基础规则仍会各自产生单事件告警；时序告警是在它们之上补的一条「链路」告警，不自动触发任何额外处置。
所有规则只证明**同组同实体内的时间先后**，不证明同一进程或同一会话的因果关系，需结合原始证据复核。
单元回放与数据库持久回放见 `validation/temporal/README.md`；尚未做生产误报率评估。
上线前用 `cmd/backtest` 的时序模式在生产只读副本上逐条回测命中量，见 [时序检测 · 回测](../docs/temporal-detection.md#回测)，
命中量不可接受的规则从发布目录里拿掉即可，规则之间互不依赖。

## 取值原则

- **窗口都不超过 15 分钟**。生产 Observe 按快照内**最大窗口**回查 `[t − 最大窗口, t + 最大窗口]` 的同资产候选，
  超过 10000 条记 `candidate_limit` 缺口、不求值；窗口拉长会让被公网扫描的主机更早触顶。需要更长窗口的链路先评估候选量。
- **序列优先于计数**。单一基础规则的计数只看次数，运维脚本循环调用就能凑够；序列要求两类不同动作按先后出现。
- **第二步选运维少做的动作**。「关防火墙 / 关 SELinux 后 `curl | sh`」正是 k3s 等安装文档的标准步骤，
  所以安全防护削弱之后只认从 `/dev/shm` 执行；清历史、清审计规则、清 syslog 在安装前出现的情况少见，才接下载执行。
- **同时间戳不算先后**（引擎语义）。同一条命令行同时命中两步（如 `sh -c "unset HISTFILE; curl … | sh"`）不构成序列。

## 规则清单

下表「基础规则」列出文件名，ID 见对应 YAML。级别除侦察计数为 medium 外均为 high。

### 认证与侦察

| ID | 类型 / 实体 | 窗口 / 阈值 | 基础规则 |
|---|---|---|---|
| `temporal:linux-auth-burst` | 计数 / 主机 | 5 分钟 ≥ 5 | `lnx_login_failure` |
| `temporal:linux-account-auth-burst` | 计数 / 账号，`min_assets: 2` | 10 分钟 ≥ 5 | `lnx_login_failure` |
| `temporal:linux-bruteforce-then-recon` | 序列 / 账号 | 10 分钟，失败 ×5 → 侦察 | `lnx_login_failure` ×5、`lin_recon_commands` |
| `temporal:windows-recon-burst` | 计数 / 主机 | 2 分钟 ≥ 6 | `win_recon_commands` |

- `linux-auth-burst`：同组同主机 5 分钟内至少 5 次 Linux 失败认证。不按账号或源 IP 分组，不同用户的失败也会累计。
  它是集中失败线索，不能直接断言账号遭到暴力破解。
- `linux-account-auth-burst`：同组同账号 10 分钟内至少 5 次失败、来自至少两台主机。单机 5 次只命中上一条，不重复告警。
  账号取事件 `username` 列，去首尾空白、转小写后比较，不做域前缀/UPN 互认；没有用户名的失败记 `no_account` 缺口。
  不同组的同名账号互不累计；资产换组后其此前的失败不再计入。
- `linux-bruteforce-then-recon`：同组同账号 10 分钟内先有 5 次失败登录，再由**同一账号**执行侦察命令
  （`whoami` / `uname -a` / `cat /etc/passwd`）。账号维度：失败登录的用户名与执行侦察的进程属主相同才关联，
  公网扫描爆破 root、运维用自己的账号排查不会连起来。10 分钟与固定的爆破得手升级（`xdr:bruteforce-success`）一致；
  中间那次成功登录没有可引用的基础规则（为每次成功登录建基础规则会让每次登录都出告警），所以不作为一步，
  是「失败集中 → 侦察」而不是严格的「失败 → 成功 → 侦察」。
  已知误报：被公网持续扫描 root 的主机上，root 的 cron / 监控脚本恰好在窗口内调用 `whoami` 或 `uname -a`；
  自己反复输错密码 5 次后登录执行 `whoami`。前者回测命中多时，按主机对 root 账号窄抑制。
- `windows-recon-burst`：同主机 2 分钟内至少 6 次侦察命令。Linux 版同口径的 `linux-recon-burst` 在生产 7 天数据上回测命中 12 次，
  全是运维自动化（AI 运维插件成批跑 `uname` / `cat /etc/os-release`），没有上线；要重新加，得先有能排除自动化来源的信号。引擎只能数事件、不能数「不同命令种类」，
  所以阈值定在手工排查（三五条）之上，只抓脚本化的密集侦察；手工侦察会漏，这是刻意取舍。
  已知误报：每分钟多次调用 `whoami` 判断身份的 cron 脚本（Linux 规则按子串匹配 `whoami`，`sh -c "whoami; …"` 父子进程各算一次）；
  RMM / 资产盘点代理成批跑 `ipconfig`、`systeminfo`、`netstat`（Windows）；平台 Pi 运维会话已按平台指令归属另行处理，
  但第三方 AI 运维插件（如 DNS 容器里的 termix-ops）不带平台标记，会被计入。

### 下载执行后建立持久化

| ID | 类型 / 实体 | 窗口 | 基础规则 |
|---|---|---|---|
| `temporal:linux-download-sensitive-file` | 序列 / 主机 | 10 分钟 | `lnx_download_exec` → `lnx_sensitive_file_change` |
| `temporal:linux-download-systemd-unit` | 序列 / 主机 | 10 分钟 | `lnx_download_exec` → `lnx_systemd_service_file` |
| `temporal:linux-download-shell-rc` | 序列 / 主机 | 10 分钟 | `lnx_download_exec` → `lnx_shell_rc_persistence` |
| `temporal:windows-lolbin-download-autostart` | 序列 / 主机 | 15 分钟 | `win_lolbin_download` → `win_registry_persistence` |
| `temporal:windows-lolbin-download-scheduled-task` | 序列 / 主机 | 15 分钟 | `win_lolbin_download` → `win_scheduled_task_file` |

- Linux 三条覆盖一句话植入后的常见落脚点：cron、authorized_keys、sudoers、ld.so.preload（敏感文件变更）、
  `/etc/systemd/system/*.service`、shell 启动文件。authorized_keys 已被文件监控覆盖（默认盯 `/root/.ssh` 与各用户 `.ssh`），
  不再另用命令行规则重复关联。10 分钟足够落地脚本跑完，短于常规运维批次间隔。
- 已知误报：`curl | sh` 形式的官方安装脚本本身就会落持久化——k3s / rancher 写 `/etc/systemd/system/*.service`，
  nvm、rustup、sdkman、oh-my-zsh、bun 改 `~/.bashrc` / `~/.profile`。包管理器装服务不经管道执行，不会命中。
  这类安装一台机器一般只发生一次，需要时按主机与时间窗临时抑制，不建议整条关闭。
- Windows 两条：certutil / bitsadmin / mshta 下载后写 Run / Winlogon 或新建/修改计划任务。注册表与计划任务来自
  persistwatch 30 秒一轮的快照，事件时间晚于真实写入，持久化在后、顺序不会反，15 分钟留出快照延迟。
  已知误报：用 bitsadmin / certutil 分发软件的老式登录脚本随后写入自启动；正常软件安装写 Run 键不经 LOLBin，不会命中。

### 凭据读取后打包、外传或外联

| ID | 类型 / 实体 | 窗口 | 基础规则 |
|---|---|---|---|
| `temporal:linux-shadow-read-archive` | 序列 / 主机 | 15 分钟 | `cred_credential_dumping` → `lnx_archive_collection` |
| `temporal:linux-shadow-read-upload` | 序列 / 主机 | 15 分钟 | `cred_credential_dumping` → SigmaHQ `proc_creation_lnx_susp_curl_fileupload` |
| `temporal:linux-ssh-key-read-archive` | 序列 / 主机 | 15 分钟 | `lnx_ssh_private_key_access` → `lnx_archive_collection` |
| `temporal:linux-ssh-key-read-upload` | 序列 / 主机 | 15 分钟 | `lnx_ssh_private_key_access` → SigmaHQ `proc_creation_lnx_susp_curl_fileupload` |
| `temporal:linux-ssh-key-read-suspicious-outbound` | 序列 / 主机 | 15 分钟 | `lnx_ssh_private_key_access` → `net_suspicious_outbound` |
| `temporal:credential-dump-suspicious-outbound` | 序列 / 主机 | 15 分钟 | `cred_credential_dumping` → `net_suspicious_outbound` |

- 读取影子库（`cat` / `cp /etc/shadow`、`unshadow`）或 SSH 私钥（新增基础规则 `lnx_ssh_private_key_access`，
  只认读取/拷贝/编码工具与 `find -name id_*`，`ssh -i`、公钥、`ssh-keygen` 不算）之后，出现打包敏感目录、
  `curl` 表单/数据上传或连 4444 / 5555 / 6667 / 31337 端口。15 分钟给手工操作留余量，仍在快照最大窗口内。
- `credential-dump-suspicious-outbound` 不限 OS：`cred_credential_dumping` 同时覆盖 Windows lsass 转储，
  `net_suspicious_outbound` 两侧都有采集；Windows 出站只有 TCP。
- 已知误报：备份脚本先 `cp /etc/shadow` 留底、15 分钟内又 `tar` 打包 `/etc`；改密码前留底影子库后马上用 `curl -d` 推送通知或调用接口
  （SigmaHQ 上传规则的 `-d` / `-F` / `-T` 判定按引擎强制不区分大小写，`curl -f` 也会命中）；
  运维用 `cat` 查看私钥后打包家目录做迁移；adb（5555）、IRC（6667）等合法业务端口外联。
  例行备份只打包、不单独读影子库或私钥，不会命中。

### 防御削弱后可疑执行

| ID | 类型 / 实体 | 窗口 | 基础规则 |
|---|---|---|---|
| `temporal:linux-history-tamper-download-exec` | 序列 / 主机 | 15 分钟 | `lnx_history_tampering` → `lnx_download_exec` |
| `temporal:linux-audit-rules-cleared-download-exec` | 序列 / 主机 | 15 分钟 | SigmaHQ `proc_creation_lnx_auditctl_clear_rules` → `lnx_download_exec` |
| `temporal:linux-syslog-cleared-download-exec` | 序列 / 主机 | 15 分钟 | SigmaHQ `proc_creation_lnx_clear_syslog` → `lnx_download_exec` |
| `temporal:linux-security-disabled-shm-exec` | 序列 / 主机 | 15 分钟 | SigmaHQ `proc_creation_lnx_security_tools_disabling` → SigmaHQ `proc_creation_lnx_susp_exec_from_dev_shm` |
| `temporal:windows-defender-exclusion-lolbin-download` | 序列 / 主机 | 15 分钟 | `win_defender_exclusion_tamper` → `win_lolbin_download` |

- 攻击者落地后先关掉记录与防护再拉载荷。运维也会清历史、清日志，但通常在安装**之后**收尾（镜像构建脚本最后 `history -c`、
  装完 `journalctl --vacuum` 腾磁盘），顺序反过来不命中。
- 防火墙 / SELinux / EDR 停用之后不接下载执行而接 `/dev/shm` 执行：关 SELinux、停 firewalld 后 `curl | sh` 是 k3s 等安装文档的原样步骤。
- `unset HISTFILE`、`history -c` 是 shell 内建命令，交互式会话里不产生进程事件；只有经 `sh -c` / `bash -c` 执行时可见
  （webshell、漏洞利用载荷常见），交互式攻击者的这一步会漏。
- Windows：先加 Defender 排除项再用 certutil 等下载。排除项来自 30 秒快照，若下载紧跟在排除项之后（30 秒内），
  快照上报时间可能晚于下载、顺序反转而漏报（回放语料以「已知缺口」用例显式记录）。
- 已知误报：清理 syslog / journal 后立刻用 `curl | sh` 装软件（如磁盘满了先腾空间再装 agent）；
  排障时 `auditctl -D` 后装软件；备份或数据库软件安装器先加排除项、再用 certutil / bitsadmin 拉组件；
  从 `/dev/shm` 运行程序的容器 / IPC 框架恰好遇到停防火墙。

## 当前格式做不到、留待引擎扩展的链路

以下方向需要时序引擎新能力，本目录没有用变通写法硬凑：

- **新进程首次出现 → 外联新目的**：首次出现是 UEBA 异步合成的 `xdr:new-process` 告警（学习期内不报，30 秒一批），
  不是 Sigma 基础规则，不进时序候选；外联「新目的」同样没有单事件基础规则。需要让时序规则引用合成信号并定义学习期内的语义。
- **序列中的「成功登录」一步**：需要「只作时序信号、不单独出告警」的基础规则，否则每次登录都会告警。
- **单步「任一基础规则」**：现在每一步只能引用一条基础规则，「读取凭据 →（打包 | 上传 | 外联）」只能拆成多条规则。
- **按不同取值计数**（如 2 分钟内至少 4 种不同侦察命令）：现在只能数事件次数。
