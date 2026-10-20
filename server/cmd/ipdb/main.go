// ipdb 下载或更新离线 IP 归属库（DB-IP Lite，CC BY 4.0）：ASN 与国家两份 mmdb，放进 IPDB_DIR。
// 只下载公开的整库文件，不发送任何要查的地址。两份都下完并校验通过才原子替换，
// 运行中的 server 下一轮（一分钟内）自动加载新库，不用重启。
//
// 用法: openxdr-ipdb [-dir 目录] [-month YYYY-MM]
//
// 不给 -month 取当月，当月还没发布（月初）退回上月；DB-IP 只保留最近两个月，更早的下不到。
// 离线环境在能联网的机器上跑完，再把两个 .mmdb 拷进目标目录（先拷成临时名再改名）即可。
package main

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"openxdr/server/internal/ipdb"
)

// 解压后的上限：现在两份各 10MB 左右，远超就是下错了东西
const maxSize = 512 << 20

var base = "https://download.db-ip.com/free"

var errNotPublished = errors.New("这个月份的库没有发布或已下架")

type source struct{ name, kind, file string }

var sources = []source{{"asn", "ASN", ipdb.ASNFile}, {"country", "Country", ipdb.CountryFile}}

func main() {
	dir := flag.String("dir", os.Getenv("IPDB_DIR"), "库目录，默认取 IPDB_DIR")
	month := flag.String("month", "", "库的月份 YYYY-MM，默认当月（未发布退回上月）")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "需要 -dir 或 IPDB_DIR")
		os.Exit(2)
	}
	if err := update(&http.Client{Timeout: 10 * time.Minute}, *dir, *month, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "更新失败:", err)
		os.Exit(1)
	}
}

func update(c *http.Client, dir, month string, now time.Time) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	months := []string{month}
	if month == "" {
		first := time.Date(now.UTC().Year(), now.UTC().Month(), 1, 0, 0, 0, 0, time.UTC)
		months = []string{first.Format("2006-01"), first.AddDate(0, -1, 0).Format("2006-01")}
	}
	err := errNotPublished
	for _, m := range months {
		var tmps []string
		tmps, err = fetchAll(c, dir, m)
		if errors.Is(err, errNotPublished) {
			continue
		}
		if err != nil {
			return err
		}
		for i, s := range sources {
			if err := os.Rename(tmps[i], filepath.Join(dir, s.file)); err != nil {
				return err
			}
		}
		// 再分发库文件（如打进镜像）要附许可与署名
		if err := os.WriteFile(filepath.Join(dir, "NOTICE"), []byte(notice(m)), 0o644); err != nil {
			return err
		}
		fmt.Printf("已更新到 %s 的库：%s\n%s", m, dir, notice(m))
		return nil
	}
	return fmt.Errorf("%v: %v", months, err)
}

func notice(month string) string {
	return "dbip-asn-lite.mmdb、dbip-country-lite.mmdb：DB-IP Lite " + month + "，IP Geolocation by DB-IP（https://db-ip.com），\n" +
		"许可 Creative Commons Attribution 4.0 International（https://creativecommons.org/licenses/by/4.0/），展示查询结果时须署名并链接 https://db-ip.com\n"
}

// fetchAll 两份都下到目录里的临时文件并校验；任何一份失败就清掉已下的
func fetchAll(c *http.Client, dir, month string) ([]string, error) {
	var tmps []string
	for _, s := range sources {
		url := fmt.Sprintf("%s/dbip-%s-lite-%s.mmdb.gz", base, s.name, month)
		tmp, err := fetch(c, dir, url, s.kind)
		if err != nil {
			for _, t := range tmps {
				_ = os.Remove(t)
			}
			return nil, err
		}
		tmps = append(tmps, tmp)
	}
	return tmps, nil
}

func fetch(c *http.Client, dir, url, kind string) (string, error) {
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return "", errNotPublished
	default:
		return "", fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return "", fmt.Errorf("%s: %w", url, err)
	}
	f, err := os.CreateTemp(dir, ".ipdb-*.mmdb")
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(zr, maxSize+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxSize {
		err = errors.New("解压后超过上限")
	}
	if err == nil {
		err = os.Chmod(f.Name(), 0o644)
	}
	if err == nil {
		err = ipdb.Validate(f.Name(), kind)
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("%s: %w", url, err)
	}
	fmt.Printf("%s  sha256 %s  (%d 字节)\n", url, hex.EncodeToString(h.Sum(nil)), n)
	return f.Name(), nil
}
