# 构建上下文是仓库根目录：server 需要 proto/ 生成代码已提交。
# 镜像自带默认规则、预设任务与 agent 安装包（发版时注入），开箱即用；挂载目录并设 RULES_PATH / TASKS_PATH / AGENT_DIST_DIR 可覆盖
FROM golang:1.26-alpine AS build
# 网络受限时可指向镜像源，例如 --build-arg GOPROXY=https://goproxy.cn,direct
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}
WORKDIR /src
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ ./
RUN CGO_ENABLED=0 go build -o /openxdr-server . && CGO_ENABLED=0 go build -o /openxdr-gencerts ./cmd/gencerts

# agent 安装包：发版时用 --build-context agents=<含 dist/ 的目录> 注入，本地构建为空目录
FROM alpine:3.22 AS agents
RUN mkdir /dist

# Pi 运行时：server 为每个会话拉起的 Node 子进程。npm ci 会先清掉拷进来的 node_modules
FROM node:22-alpine AS pi-runtime
WORKDIR /pi-runtime
COPY server/pi-runtime/ ./
RUN npm ci --omit=dev --ignore-scripts

FROM alpine:3.22
# node 依赖 libstdc++；chromium + 中文字体渲染报告，Poppler 将 PDF 页面渲染为视觉模型输入
# 国内构建可传 ALPINE_MIRROR（如 https://mirrors.ustc.edu.cn），默认官方源
ARG ALPINE_MIRROR=
RUN if [ -n "$ALPINE_MIRROR" ]; then sed -i -E "s#https?://dl-cdn.alpinelinux.org#$ALPINE_MIRROR#" /etc/apk/repositories; fi && \
    apk add --no-cache libstdc++ chromium font-noto-cjk poppler-utils && adduser -D -u 10001 openxdr
COPY --from=build /openxdr-server /usr/local/bin/openxdr-server
COPY --from=build /openxdr-gencerts /usr/local/bin/openxdr-gencerts
COPY rules/ /opt/openxdr/rules/
COPY tasks/ /opt/openxdr/tasks/
# 时序规则随镜像带上，但默认不启用（开发中）：设 TEMPORAL_RULES_PATH=/opt/openxdr/temporal-rules 开启
COPY temporal-rules/ /opt/openxdr/temporal-rules/
COPY --from=agents /dist/ /opt/openxdr/dist/
ENV RULES_PATH=/opt/openxdr/rules TASKS_PATH=/opt/openxdr/tasks AGENT_DIST_DIR=/opt/openxdr/dist
COPY --from=pi-runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=pi-runtime /pi-runtime /app/pi-runtime
USER openxdr
EXPOSE 8080 8081
ENTRYPOINT ["openxdr-server"]
