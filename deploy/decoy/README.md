# Linux 诱饵服务部署

适用 systemd 250+ 的 Linux，支持专用 SSH、HTTP 和文件诱饵；模拟 Shell 继续交互运行。此流程由运维在授权主机上执行，不通过平台 EXEC 传递秘密。配置生成器本身不安装、不联网、不读取令牌。

## 构建并生成配置

在 `server/` 构建与目标架构一致的二进制：

```sh
go build -o /tmp/aidr-decoyhost ./cmd/decoyhost
go build -o /tmp/aidr-decoyunit ./cmd/decoyunit
```

从控制台登记取得 UUID，以下变量不含秘密。`kind` 必须与登记一致，运行端启动时再次核对。默认仅回环监听；内网监听需要显式填写目标 IP。服务不授予低端口绑定能力，SSH/HTTP 登记应使用 1024 以上端口。

```sh
decoy_id=11111111-1111-4111-8111-111111111111
/tmp/aidr-decoyunit -platform https://aidr.example.internal \
  -deployment "$decoy_id" -kind http > "/tmp/aidr-decoy-$decoy_id.service"
```

审查生成文件。SSH/HTTP 使用动态用户（文件载体见下文），只读系统目录、资源上限和每登记独立的状态目录；运行令牌通过 `LoadCredential` 加载，不写入 unit 或环境变量。服务禁止自动重启，避免认证失败循环以及异常文件残留被静默覆盖。

## 显式安装与启动

将二进制通过现有受控发布渠道复制到主机，核对其来源与哈希。令牌由控制台单独签发，经已核对主机身份的安全通道放入一个仅管理员可读的临时文件；下面的 `/受控目录/runtime-token` 是该文件路径，不是令牌内容。

```sh
sudo install -d -o root -g root -m 0755 /usr/local/libexec
sudo install -o root -g root -m 0755 /tmp/aidr-decoyhost /usr/local/libexec/aidr-decoyhost
sudo install -d -o root -g root -m 0700 "/etc/aidr-decoy/$decoy_id"
sudo install -o root -g root -m 0600 /受控目录/runtime-token "/etc/aidr-decoy/$decoy_id/token"
sudo install -o root -g root -m 0644 "/tmp/aidr-decoy-$decoy_id.service" "/etc/systemd/system/aidr-decoy-$decoy_id.service"
sudo systemd-analyze verify "/etc/systemd/system/aidr-decoy-$decoy_id.service"
sudo systemctl daemon-reload
sudo systemctl enable --now "aidr-decoy-$decoy_id.service"
```

SSH 类型还需在启动前生成专用、不与真实 sshd 共用的主机密钥，放在 `/etc/aidr-decoy/<UUID>/host-key`，root 所有且权限 0600。不要把密码或令牌作为命令参数、粘进 Shell 历史或平台执行命令。

启动成功需分别检查 `systemctl status`、控制台运行租约以及专用端点可达性；systemd active 不等于诱饵已完成启动。平台 TLS 证书须被主机信任，不提供跳过校验选项。

文件载体生成 unit 时用 `-file-root <目录>` 指定父目录：须已存在、root 所有且属组与其他用户不可写，选业务用户会浏览的位置（如共享目录）。诱饵建在其下 `archive-<UUID>/`，root 所有、所有人可读。动态用户的状态目录在 `/var/lib/private`（0700）下，普通用户看不到，所以文件载体不用动态用户，改以清空全部 capability 的 root 运行，`ProtectSystem=strict` 下只有该父目录可写。系统目录（`/etc`、`/usr`、`/proc` 等）与运行端自身目录一律拒绝。

## 轮换、停止和撤销

正常轮换先 `systemctl stop`，确认平台收到退出回报，然后在控制台轮换令牌，替换 root 所有的凭据文件，再启动服务。systemd 在启动时加载凭据，替换源文件不会更新正在运行的进程。失联时新实例可能要等待 90 秒租约过期。

正常撤销先停止并禁用服务，确认状态，再撤销控制台登记：

```sh
sudo systemctl disable --now "aidr-decoy-$decoy_id.service"
```

紧急情况下可先在控制台撤销令牌，但仍需在主机确认进程退出；断网进程并不受服务端强制控制。正常文件退出会核验原内容再删除，遇到外部修改则保留并报错。异常退出的残留也不自动覆盖；管理员检查后再处理，不要递归删除可能含有调查证据的目录。

卸载前先确认停止，随后移除本登记的 unit 与凭据文件、执行 `daemon-reload`。共享二进制可能供其他登记使用，不随单个登记撤销删除。

凭据与动态用户机制参考 [systemd 官方文档](https://www.freedesktop.org/software/systemd/man/250/systemd.exec.html)。此处为手工部署流程。控制台远程安装的开关、限制与状态语义见 [设计说明](../../docs/multi-carrier-decoys.md#控制台远程安装)；远程安装使用每登记 `/opt/aidr-decoy/<UUID>/decoyhost`，不覆盖本页的共享二进制路径。远程安装脚本已完成 systemd 252 隔离容器验收，真实目标主机与生产端到端验收仍未完成，详见设计说明的凭据启动回归章节。
