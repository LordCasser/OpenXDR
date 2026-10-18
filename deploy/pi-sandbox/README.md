# Pi 沙箱（原型）

让 Pi 用自己的默认工具（bash/read/write/edit）工作，用 Skill 引导，而不是平台自定义的工具 schema。
沙箱是独立容器，**没有任何平台密钥**；唯一的凭据是运行时注入的会话工具令牌 `XDR_TOKEN`。

- `xdr`：沙箱通往平台的唯一出口，调用 `POST /api/sandbox/tool`（令牌鉴权）。能做什么由令牌绑定的会话决定：
  组、发起人、高风险命令名单与审批、只读查询身份、审计，与会话内的 Pi 完全相同。
- 令牌：会话发起人调用 `POST /api/agent-sessions/{id}/sandbox-token` 签发，4 小时有效，库里只存哈希；
  每次调用按发起人当前的组内角色复核，降权即失效。审批在沙箱调用里最多等 2 分钟。
- `pi-agent/`：模型与思考配置（GLM 思考 high、跨轮保留），以及 `skills/openxdr/SKILL.md` 工作手册。

```bash
docker build -t openxdr-pi-sandbox:proto deploy/pi-sandbox
docker run --rm -e HTTP_PROXY= -e HTTPS_PROXY= -e XDR_URL=https://<控制台> -e XDR_TOKEN=<令牌> \
  openxdr-pi-sandbox:proto -p "巡检本组主机"
```

运行容器时要清掉 Docker 注入的代理变量：Node 不认 `NO_PROXY` 里的网段写法，内网模型请求会被送进代理。
生产化还需要：按会话起停容器、网络只放行平台 API 与模型端点、资源限额、会话记录回写平台。
