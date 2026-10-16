package enroll

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Dist AGENT_DIST_DIR 里的 agent 安装包。安装脚本从这里下载，在线 agent 也按这里的版本自动升级。
type Dist struct {
	Dir string

	mu    sync.Mutex
	cache map[string]distEntry
}

type distEntry struct {
	size    int64
	modTime time.Time
	sha256  string
}

// files 可分发的平台与文件名。
var files = map[string]string{
	"linux-amd64":   "openxdr-agent-linux-amd64",
	"linux-arm64":   "openxdr-agent-linux-arm64",
	"windows-amd64": "openxdr-agent-windows-amd64.exe",
}

// arches Rust std::env::consts::ARCH 到分发平台后缀。
var arches = map[string]string{"x86_64": "amd64", "aarch64": "arm64"}

// Platform agent 上报的 os/arch 对应的分发平台，不支持时返回空。
func Platform(os, arch string) string {
	p := os + "-" + arches[arch]
	if _, ok := files[p]; !ok {
		return ""
	}
	return p
}

func (d *Dist) path(platform string) (string, bool) {
	name, ok := files[platform]
	if !ok || d == nil || d.Dir == "" {
		return "", false
	}
	return filepath.Join(d.Dir, name), true
}

// Available 实际放了安装包的平台。
func (d *Dist) Available() []string {
	var out []string
	for p := range files {
		if path, ok := d.path(p); ok {
			if st, err := os.Stat(path); err == nil && st.Mode().IsRegular() {
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out
}

// SHA256 平台安装包的哈希，没有安装包返回空。文件没变就用缓存，不每次注册都重算。
func (d *Dist) SHA256(platform string) string {
	path, ok := d.path(platform)
	if !ok {
		return ""
	}
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return ""
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if e, ok := d.cache[platform]; ok && e.size == st.Size() && e.modTime.Equal(st.ModTime()) {
		return e.sha256
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if d.cache == nil {
		d.cache = map[string]distEntry{}
	}
	d.cache[platform] = distEntry{st.Size(), st.ModTime(), sum}
	return sum
}

// Open 打开平台安装包。
func (d *Dist) Open(platform string) (*os.File, error) {
	path, ok := d.path(platform)
	if !ok {
		return nil, os.ErrNotExist
	}
	return os.Open(path)
}
