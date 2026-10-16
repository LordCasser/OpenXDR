#!/bin/sh
set -eu

runtime=${1:-runtime}

for file in patroni.yml nats.conf keepalived.conf; do
  test -f "$runtime/$file" || {
    echo "缺少 $runtime/$file，请先运行 render.py" >&2
    exit 1
  }
done
test -d "$runtime/secrets" || { echo "缺少 $runtime/secrets" >&2; exit 1; }
test -d "$runtime/app-certs" || { echo "缺少 $runtime/app-certs" >&2; exit 1; }

# postgres:16-alpine 的 postgres UID 为 70；server 镜像固定使用 UID 10001。
chown 70:70 "$runtime/patroni.yml"
chmod 600 "$runtime/patroni.yml" "$runtime/nats.conf" "$runtime/keepalived.conf"
chown -R 70:70 "$runtime/secrets"
find "$runtime/secrets" -type d -exec chmod 700 {} +
find "$runtime/secrets" -type f -name '*.key' -exec chmod 600 {} +
find "$runtime/secrets" -type f ! -name '*.key' -exec chmod 640 {} +
chown -R 10001:10001 "$runtime/app-certs"
find "$runtime/app-certs" -type d -exec chmod 700 {} +
find "$runtime/app-certs" -type f -exec chmod 600 {} +
