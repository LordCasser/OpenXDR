# Pi 沙箱原型：默认工具（bash/read/write/edit）+ xdr 命令行，容器里没有任何平台密钥。
# 唯一的平台凭据是运行时注入的会话工具令牌（XDR_TOKEN），只能调用该会话被允许的工具。
FROM node:24-bookworm-slim
ARG NPM_REGISTRY=https://registry.npmmirror.com
RUN sed -i 's|deb.debian.org|mirrors.ustc.edu.cn|g' /etc/apt/sources.list.d/debian.sources \
 && apt-get update && apt-get install -y --no-install-recommends bash curl jq ca-certificates python3 bsdextrautils \
 && rm -rf /var/lib/apt/lists/*
RUN npm install -g --registry=$NPM_REGISTRY @earendil-works/pi-coding-agent@0.85.1
RUN useradd -m -u 10010 agent
COPY xdr /usr/local/bin/xdr
COPY --chown=agent:agent pi-agent/ /home/agent/.pi/agent/
USER agent
WORKDIR /home/agent/work
ENTRYPOINT ["pi"]
