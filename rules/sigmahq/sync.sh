#!/bin/sh
# 从 SigmaHQ 仓库同步本平台用得上的规则：Linux 进程 / 文件 / 网络与 DNS，再按 excluded.txt 剔除回测不过的。
# 用法: sh rules/sigmahq/sync.sh <sigma 仓库目录>
# 同步后跑 sigmacheck --strict 与 detectcheck --strict，并用 cmd/backtest 在生产数据上回测新增规则。
set -eu
src=${1:?需要 SigmaHQ 仓库目录}
here=$(cd "$(dirname "$0")" && pwd)
for d in linux/process_creation linux/file_event linux/network_connection network/dns; do
  rm -rf "$here/$d"
  mkdir -p "$here/$(dirname "$d")"
  cp -r "$src/rules/$d" "$here/$d"
done
grep -v '^#' "$here/excluded.txt" | while read -r f; do [ -n "$f" ] && rm -f "$here/$f"; done
echo "同步自 $(git -C "$src" log -1 --format='%h %cd' --date=short)：$(find "$here" -name '*.yml' | wc -l) 条规则"
