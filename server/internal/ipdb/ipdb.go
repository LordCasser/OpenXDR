// Package ipdb 离线 IP 归属库：在本地 mmdb 文件里查 AS 号、AS 组织名与国家，不向任何外部服务发送地址。
// 数据用 DB-IP Lite（CC BY 4.0，展示时须署名并链接 https://db-ip.com），每月更新，见 cmd/ipdb 与 docs/asset-map.md。
// 同结构的 GeoLite2-ASN / GeoLite2-Country 改成下面的文件名也能用（许可由使用者自行遵守）。
package ipdb

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

const (
	ASNFile     = "dbip-asn-lite.mmdb"
	CountryFile = "dbip-country-lite.mmdb"
)

// Info 一个地址在离线库里的归属；库缺失或没有记录的部分为零值
type Info struct {
	ASN     int
	Org     string
	Country string
}

// DB 目录里的两份库，各自可缺。文件被替换（更新命令原子改名）后下一次 Refresh 重新打开，不用重启。
// 只给一个 goroutine 用（地址信息补全的后台轮），不加锁
type DB struct {
	Dir          string
	asn, country handle
	logged       bool
}

type handle struct {
	r    *maxminddb.Reader
	mod  time.Time
	size int64
}

// Refresh 打开或重新打开有变化的库文件；状态变了（含第一次）记一条日志，库缺失只说一次。nil 当没配置
func (d *DB) Refresh() {
	if d == nil {
		return
	}
	if d.Dir == "" {
		if !d.logged {
			d.logged = true
			slog.Info("未配置 IPDB_DIR：公网地址不填离线归属（AS / 国家）")
		}
		return
	}
	a := d.asn.reload(filepath.Join(d.Dir, ASNFile), "ASN")
	c := d.country.reload(filepath.Join(d.Dir, CountryFile), "Country")
	if d.logged && !a && !c {
		return
	}
	d.logged = true
	if !d.Ready() {
		slog.Info("离线 IP 归属库缺失：公网地址不填 AS / 国家，放入库文件后自动加载（更新方法见 docs/asset-map.md）", "dir", d.Dir)
		return
	}
	slog.Info("离线 IP 归属库已加载", "dir", d.Dir, "asn", d.asn.built(), "country", d.country.built())
}

// Ready 至少有一份库可查
func (d *DB) Ready() bool { return d != nil && (d.asn.r != nil || d.country.r != nil) }

// Lookup 查一个地址；是不是公网由调用方判断。库里的数据也当不可信输入，解码不了就当没有
func (d *DB) Lookup(a netip.Addr) Info {
	var out Info
	if d == nil {
		return out
	}
	a = a.Unmap()
	if d.asn.r != nil {
		var v struct {
			Number uint32 `maxminddb:"autonomous_system_number"`
			Org    string `maxminddb:"autonomous_system_organization"`
		}
		if d.asn.r.Lookup(a).Decode(&v) == nil {
			out.ASN, out.Org = int(v.Number), v.Org
		}
	}
	if d.country.r != nil {
		var v struct {
			Country struct {
				ISO string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if d.country.r.Lookup(a).Decode(&v) == nil {
			out.Country = v.Country.ISO
		}
	}
	return out
}

func (d *DB) Close() {
	d.asn.close()
	d.country.close()
}

// reload 文件有变化才重开；打不开保留原来的，并记下这次的版本，免得每轮重试刷日志。
// 文件不在了也保留原来的：已映射的旧库照样能查
func (h *handle) reload(path, kind string) bool {
	st, err := os.Stat(path)
	if err != nil || (st.ModTime().Equal(h.mod) && st.Size() == h.size) {
		return false
	}
	h.mod, h.size = st.ModTime(), st.Size()
	r, err := open(path, kind)
	if err != nil {
		slog.Warn("离线 IP 库打不开，继续用原来的", "file", path, "err", err)
		return false
	}
	h.close()
	h.r = r
	return true
}

func (h *handle) close() {
	if h.r != nil {
		_ = h.r.Close()
		h.r = nil
	}
}

func (h *handle) built() string {
	if h.r == nil {
		return "缺失"
	}
	return h.r.Metadata.BuildTime().UTC().Format(time.DateOnly)
}

// open 打开并核对库类型（metadata 的 database_type 要含 kind），防止两份文件放反
func open(path, kind string) (*maxminddb.Reader, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	if t := r.Metadata.DatabaseType; !strings.Contains(t, kind) {
		_ = r.Close()
		return nil, fmt.Errorf("库类型是 %q，不是 %s 库", t, kind)
	}
	return r, nil
}

// probe 真实库里一定有记录的地址：更新命令用它确认下到的是完整的库，而不是错误页或截断的文件
var probe = netip.MustParseAddr("8.8.8.8")

// Validate 更新命令落盘前的完整检查：结构校验、库类型、探测地址有记录
func Validate(path, kind string) error {
	r, err := open(path, kind)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := r.Verify(); err != nil {
		return fmt.Errorf("结构校验失败: %w", err)
	}
	if !r.Lookup(probe).Found() {
		return errors.New("库里查不到 " + probe.String() + "，不像完整的库")
	}
	return nil
}
