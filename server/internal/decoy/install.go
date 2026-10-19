package decoy

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// InstallScript 只嵌入管理员配置目录中的 Linux ELF；正文通过 SSH stdin 发送，禁止记录。
func InstallScript(dir, arch, platform, id, kind, listen, fileRoot string) (string, error) {
	unit, err := ServiceUnit(platform, id, kind, listen, fileRoot)
	if err != nil {
		return "", err
	}
	machine := elf.EM_X86_64
	uname := "x86_64"
	switch arch {
	case "amd64":
	case "arm64":
		machine = elf.EM_AARCH64
		uname = "aarch64"
	default:
		return "", fmt.Errorf("只支持 Linux amd64/arm64")
	}
	if dir == "" {
		return "", fmt.Errorf("未配置诱饵安装包目录")
	}
	f, err := os.Open(filepath.Join(dir, "decoyhost-linux-"+arch))
	if err != nil {
		return "", fmt.Errorf("诱饵安装包不可用")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 32<<20 {
		return "", fmt.Errorf("安装包类型或大小无效")
	}
	data, err := io.ReadAll(io.LimitReader(f, (32<<20)+1))
	if err != nil || len(data) > 32<<20 {
		return "", fmt.Errorf("读取安装包失败")
	}
	binary, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("安装包必须为 Linux ELF")
	}
	defer binary.Close()
	if binary.Machine != machine || binary.Class != elf.ELFCLASS64 {
		return "", fmt.Errorf("安装包架构不匹配")
	}
	for _, p := range binary.Progs {
		if p.Type == elf.PT_INTERP {
			return "", fmt.Errorf("安装包须静态构建（CGO_ENABLED=0）")
		}
	}
	root := "/opt/aidr-decoy/" + id
	unit = strings.Replace(unit, "/usr/local/libexec/aidr-decoyhost", root+"/decoyhost", 1)
	sshKey, carrier := "", ""
	switch kind {
	case "ssh":
		sshKey = "ssh-keygen -q -t ed25519 -N '' -f \"$config/host-key\"\n"
		carrier = "command -v ssh-keygen >/dev/null"
	case "file":
		// 父目录须已存在且只有 root 可写：清理前的内容核对依赖外人改不了它。
		carrier = fmt.Sprintf(`[ -d %[1]s ] && [ ! -L %[1]s ] && [ "$(stat -c %%u %[1]s)" = 0 ]
case "$(stat -c %%a %[1]s)" in 700|711|750|751|755) ;; *) exit 1;; esac
[ ! -e %[1]s/archive-%[2]s ] && [ ! -L %[1]s/archive-%[2]s ] || exit 1`, fileRoot, id)
	}
	// 所有插值已按类型校验或编码；令牌来自 hostimport.Install 的固定位置参数。
	return fmt.Sprintf(`set -eu
umask 077
[ "$(id -u)" = 0 ]
[ "$(uname -s)" = Linux ]
[ "$(uname -m)" = %s ]
[ "$(systemctl --version | head -n 1 | awk '{print $2}')" -ge 250 ]
command -v base64 >/dev/null
command -v sha256sum >/dev/null
command -v systemctl >/dev/null
%s
safe_dir() {
 if [ ! -e "$1" ] && [ ! -L "$1" ]; then mkdir -m 0700 "$1"; fi
 [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %%u "$1")" = 0 ] || exit 1
 case "$(stat -c %%a "$1")" in 700|750|755) ;; *) exit 1;; esac
}
[ -d /opt ] && [ ! -L /opt ] && [ "$(stat -c %%u /opt)" = 0 ] && [ "$(stat -c %%a /opt)" = 755 ] || exit 1
if [ ! -e /opt/aidr-decoy ] && [ ! -L /opt/aidr-decoy ]; then mkdir -m 0755 /opt/aidr-decoy; fi
[ -d /opt/aidr-decoy ] && [ ! -L /opt/aidr-decoy ] && [ "$(stat -c %%u /opt/aidr-decoy)" = 0 ] && [ "$(stat -c %%a /opt/aidr-decoy)" = 755 ] || exit 1
safe_dir /etc
safe_dir /etc/aidr-decoy
safe_dir /etc/systemd
safe_dir /etc/systemd/system
root=%s
config=/etc/aidr-decoy/%s
unit=/etc/systemd/system/aidr-decoy-%s.service
[ ! -e "$root" ] && [ ! -L "$root" ] || exit 1
[ ! -e "$config" ] && [ ! -L "$config" ] || exit 1
[ ! -e "$unit" ] && [ ! -L "$unit" ] || exit 1
[ ! -e /var/lib/aidr-decoy-%s ] && [ ! -L /var/lib/aidr-decoy-%s ] || exit 1
stage=$(mktemp -d /tmp/aidr-decoy.XXXXXXXX)
trap 'rm -rf -- "$stage"' EXIT
trap 'exit 1' HUP INT TERM
base64 -d > "$stage/decoyhost" <<'AIDR_BINARY'
%s
AIDR_BINARY
printf '%%s  %%s\n' '%x' "$stage/decoyhost" | sha256sum -c - >/dev/null
chmod 0755 "$stage/decoyhost"
base64 -d > "$stage/unit" <<'AIDR_UNIT'
%s
AIDR_UNIT
# 独占创建；失败后保留已创建目录供核查，不覆盖或自动回滚现场。
mkdir -m 0755 "$root"
mkdir -m 0700 "$config"
install -m 0755 "$stage/decoyhost" "$root/decoyhost"
printf '%%s' "$2" > "$config/token"
chmod 0600 "$config/token"
%s
(set -C; cat "$stage/unit" > "$unit")
chmod 0644 "$unit"
systemd-analyze verify "$unit"
systemctl daemon-reload
systemctl enable --now aidr-decoy-%s.service
`, uname, carrier, root, id, id, id, id, base64.StdEncoding.EncodeToString(data), sha256.Sum256(data), base64.StdEncoding.EncodeToString([]byte(unit)), sshKey, id), nil
}
