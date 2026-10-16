#!/bin/sh
# OpenXDR agent 一键安装（Linux）。在控制台「添加主机」复制命令执行：
#   curl -fsSL <控制台>/api/enroll/install.sh | sudo sh -s -- <控制台> <令牌>
# 重复执行即重装：旧二进制保留为 openxdr-agent.prev，私钥与证书重新生成。
set -eu

BASE=${1:?缺少控制台地址}
TOKEN=${2:?缺少接入令牌}
DIR=/etc/openxdr
BIN=/usr/local/bin/openxdr-agent
UNIT=/etc/systemd/system/openxdr-agent.service

[ "$(id -u)" = 0 ] || { echo "需要 root 权限，请用 sudo 执行" >&2; exit 1; }
command -v curl >/dev/null || { echo "需要 curl" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "需要 systemd" >&2; exit 1; }
case $(uname -m) in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) echo "不支持的架构：$(uname -m)" >&2; exit 1 ;;
esac

echo "下载 agent（linux-$ARCH）"
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
curl -fsSL "$BASE/api/enroll/agent/linux-$ARCH" -o "$TMP"
chmod 755 "$TMP"
"$TMP" version >/dev/null

echo "签发主机证书并接入"
mkdir -p "$DIR"
chmod 700 "$DIR"
"$TMP" enroll-request "$DIR" |
  curl -fsS -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    --data-binary @- "$BASE/api/enroll/register" |
  "$TMP" enroll-apply "$DIR"

[ -f "$BIN" ] && cp -a "$BIN" "$BIN.prev"
mv "$TMP" "$BIN"
trap - EXIT

cat >"$UNIT" <<'UNIT'
[Unit]
Description=OpenXDR endpoint agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/openxdr/agent.env
ExecStart=/usr/local/bin/openxdr-agent
Restart=always
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable openxdr-agent >/dev/null 2>&1
systemctl restart openxdr-agent
echo "完成：$(hostname) 已接入，几秒后会出现在控制台资产列表"
