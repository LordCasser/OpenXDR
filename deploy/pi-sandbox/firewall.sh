#!/bin/sh
# 沙箱主机防火墙：容器出口只放行模型端点，容器不能访问宿主；sandboxd 端口只对平台节点开放。
# 规则放在自有链里，重复执行只会重建自有链；Docker 不管 DOCKER-USER，重启 docker 也不会冲掉。
# 用法：MODEL_ENDPOINTS="10.0.0.5:8000 ..." PLATFORM_NODES="10.0.0.1 10.0.0.2" sh firewall.sh
set -eu
BRIDGE=${SANDBOX_BRIDGE:-br-sandbox}
PORT=${SANDBOXD_PORT:-8090}
: "${MODEL_ENDPOINTS:?需要 MODEL_ENDPOINTS（模型端点 IP:端口，空格分隔）}"
: "${PLATFORM_NODES:?需要 PLATFORM_NODES（server 节点 IP，空格分隔）}"

chain() { iptables -N "$1" 2>/dev/null || iptables -F "$1"; iptables -C "$2" -j "$1" 2>/dev/null || iptables -I "$2" 1 -j "$1"; }

chain OPENXDR-SBX-FWD DOCKER-USER
iptables -A OPENXDR-SBX-FWD -o "$BRIDGE" -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
iptables -A OPENXDR-SBX-FWD -o "$BRIDGE" -j DROP
iptables -A OPENXDR-SBX-FWD -i "$BRIDGE" -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
for ep in $MODEL_ENDPOINTS; do
  iptables -A OPENXDR-SBX-FWD -i "$BRIDGE" -p tcp -d "${ep%:*}" --dport "${ep##*:}" -j RETURN
done
iptables -A OPENXDR-SBX-FWD -i "$BRIDGE" -j DROP

chain OPENXDR-SBX-IN INPUT
iptables -A OPENXDR-SBX-IN -i "$BRIDGE" -j DROP
for ip in $PLATFORM_NODES; do
  iptables -A OPENXDR-SBX-IN -p tcp -s "$ip" --dport "$PORT" -j RETURN
done
iptables -A OPENXDR-SBX-IN -p tcp --dport "$PORT" -j DROP
echo "沙箱防火墙已生效：出口 $MODEL_ENDPOINTS，平台 $PLATFORM_NODES"
