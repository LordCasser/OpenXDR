# Windows 处置后状态复核

`verify-response.py` 读取已成功的处置指令，在同一资产上通过平台正常 exec 权限链发起只读 PowerShell
探测。它不重放处置、不自动写有效性结论、不结案。仅用于有明确授权的测试或运维目标。

```sh
python3 deploy/pilot/verify-response.py \
  --base-url https://<平台地址> \
  --cookie-file /私有目录/session-cookie.json \
  --command <已成功处置的指令UUID> \
  --probe <处置前确认可达的IP:端口> \
  --output /私有目录/verification.json
```

Cookie 文件内容为 JSON 字符串，使用有效平台会话，文件权限设为 0600，用后注销并删除。
文件和账号动作不传 `--probe`；网络动作只接受数字 IP，IPv6 使用 `[地址]:端口`。
封锁/解封探测必须落在原目标 IP 或 CIDR 内；域名封锁不猜测解析结果。
支持隔离/解除隔离、封锁/解封、文件隔离/恢复、账号禁用/启用；不根据可复用的 PID 猜测原进程状态。

输出包含原指令、探测指令 UUID、回执、当前状态与 `state_matches`。输出为 `observed` 只表示取得
结构化观察结果；只有 `state_matches=true` 表示与该动作的预期状态一致。
文件恢复的 SHA256 仍需和处置前哈希比较；账号还需结合会话、认证来源检查。
网络探测失败也可能源于目标服务故障，须结合处置前基线、放行的管理通道与解除后的恢复结果判断。
历史动作之后若执行过反向动作，当前状态自然不会再匹配历史动作，不能据此断言历史执行失败。

失败或超时为不确定，POST 不自动重试。输出停留在 `dispatching` 时先查平台指令和审计记录，
确认是否已下发；不要直接重跑。HTTP 异常会退出，保留最后状态，需同样核查。
报告包含路径、用户名和主机信息，按私有证据保存。与事件证据核对后，管理员可通过平台现有处置复核
入口人工登记结论（见 `docs/response-verification.md`）。

离线边界测试：`python3 -m unittest discover -s deploy/pilot -p 'test_verify_response.py'`。

## 2026-10-22 实测

在授权测试主机 `OPENXDR-TESTWIN` 上，以已成功的解除隔离指令为来源，发起只读 TCP 状态探测。
结果为 `observed`、`state_matches=true`，探测指令为
`01a162ea-9795-7895-b224-0f9f881d9bf3`，平台回执成功且存在一条对应的 `command_issued` 审计记录。
本次工具验收仅证明该主机当时能够访问指定业务端口；文件、账号模板通过参数边界检查，
本次没有用此工具重新执行文件或账号的实机测试，也没有自动登记处置有效或结案。
