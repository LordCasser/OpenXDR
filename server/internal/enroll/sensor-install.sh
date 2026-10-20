#!/bin/sh
# OpenXDR 流量探针一键安装（Linux）。在控制台「添加主机 → 流量探针」复制命令执行：
#   curl -fsSL <控制台>/api/enroll/sensor-install.sh | sudo sh -s -- <控制台> <令牌> <抓包网卡>
# 抓哪块网卡决定能看见哪些流量，不替用户猜：不带网卡参数时只列出本机网卡后退出。
# 重复执行即重装：旧二进制保留为 openxdr-sensor.prev，私钥与证书重新生成。
set -eu

BASE=${1:?缺少控制台地址}
TOKEN=${2:?缺少接入令牌}
IFACE=${3:-}
# 脚本、二进制与令牌都从这个地址走，明文传输等于把主机 root 交给中间人
case "$BASE" in
  https://*) ;;
  *) echo "接入需要可信 HTTPS 控制台地址" >&2; exit 1 ;;
esac
DIR=/etc/openxdr
BIN=/usr/local/bin/openxdr-sensor
UNIT=/etc/systemd/system/openxdr-sensor.service

list_ifaces() {
  echo "本机网卡（名称 / 状态 / 地址）：" >&2
  for d in /sys/class/net/*; do
    n=${d##*/}
    [ "$n" = lo ] && continue
    state=$(cat "$d/operstate" 2>/dev/null || echo unknown)
    addrs=$(ip -o addr show dev "$n" 2>/dev/null | awk '{printf "%s ", $4}')
    printf '  %-16s %-8s %s\n' "$n" "$state" "$addrs" >&2
  done
  echo "选反代网关的公网口，或交换机镜像口对应的网卡，作为第三个参数重新执行。" >&2
}

if [ -z "$IFACE" ]; then
  echo "未指定抓包网卡。" >&2
  list_ifaces
  exit 2
fi
# 网卡名进 systemd unit，只收内核网卡名允许的字符
case "$IFACE" in
  *[!A-Za-z0-9._-]* | lo) echo "网卡名不合法：$IFACE" >&2; exit 2 ;;
esac
if [ ${#IFACE} -gt 15 ] || [ ! -e "/sys/class/net/$IFACE" ]; then
  echo "网卡不存在：$IFACE" >&2
  list_ifaces
  exit 2
fi

[ "$(id -u)" = 0 ] || { echo "需要 root 权限，请用 sudo 执行" >&2; exit 1; }
command -v curl >/dev/null || { echo "需要 curl" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "需要 systemd" >&2; exit 1; }
case $(uname -m) in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) echo "不支持的架构：$(uname -m)" >&2; exit 1 ;;
esac

echo "下载 sensor（linux-$ARCH）"
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
curl -fsSL "$BASE/api/enroll/sensor/linux-$ARCH" -o "$TMP"
chmod 755 "$TMP"
"$TMP" version >/dev/null

echo "签发探针证书并接入"
mkdir -p "$DIR"
chmod 700 "$DIR"
GRANT=$(mktemp)
trap 'rm -f "$TMP" "$GRANT"' EXIT
# 不用 curl -f：被拒绝时要把 server 给的原因原样告诉用户
CODE=$("$TMP" enroll-request "$DIR" |
  curl -sS -o "$GRANT" -w '%{http_code}' -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" --data-binary @- "$BASE/api/enroll/register")
if [ "$CODE" != 200 ]; then
  echo "接入被拒绝（HTTP $CODE）：$(cat "$GRANT")" >&2
  exit 1
fi
"$TMP" enroll-apply "$DIR" <"$GRANT"

[ -f "$BIN" ] && cp -a "$BIN" "$BIN.prev"
mv "$TMP" "$BIN"
rm -f "$GRANT"
trap - EXIT

cat >"$UNIT" <<UNIT
[Unit]
Description=OpenXDR network sensor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/openxdr/sensor.env
Environment=SENSOR_IFACE=$IFACE
ExecStart=/usr/local/bin/openxdr-sensor
Restart=always
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable openxdr-sensor >/dev/null 2>&1
systemctl restart openxdr-sensor
echo "完成：$(hostname) 的流量探针已接入，抓包网卡 $IFACE，几秒后可在控制台资产详情看到抓包状态"
