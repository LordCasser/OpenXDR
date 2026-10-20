// 生成单测用的小 mmdb：只含文档保留网段的假数据，结构与 DB-IP Lite 的 ASN / 国家库一致。
// 独立 module，不进 server 的依赖；改了数据在本目录 go run . 重新生成（输出到上一级目录）
package main

import (
	"log"
	"net"
	"os"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func main() {
	write("../dbip-asn-lite.mmdb", "Test-ASN", map[string]mmdbtype.Map{
		"203.0.113.0/25":  asn(64500, "Example Net A"),
		"198.51.100.0/24": asn(64501, "Example Net B"),
		"2001:db8:1::/48": asn(64502, "Example Net V6"),
		// 私网段：库里有也不该被查（由调用方按公网判断挡掉）
		"10.0.0.0/8": asn(64999, "Private Should Not Show"),
		// 更新命令的完整性探测地址
		"8.8.8.0/24": asn(64510, "Probe Net"),
	})
	write("../dbip-country-lite.mmdb", "Test-Country", map[string]mmdbtype.Map{
		"203.0.113.0/24":  country("AU"),
		"2001:db8:1::/48": country("JP"),
		"8.8.8.0/24":      country("US"),
	})
}

func asn(n uint32, org string) mmdbtype.Map {
	return mmdbtype.Map{"autonomous_system_number": mmdbtype.Uint32(n), "autonomous_system_organization": mmdbtype.String(org)}
}

func country(iso string) mmdbtype.Map {
	return mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(iso)}}
}

func write(path, kind string, data map[string]mmdbtype.Map) {
	t, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: kind, Description: map[string]string{"en": "OpenXDR test " + kind}, RecordSize: 24, IncludeReservedNetworks: true})
	if err != nil {
		log.Fatal(err)
	}
	for cidr, v := range data {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatal(err)
		}
		if err := t.Insert(n, v); err != nil {
			log.Fatal(err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if _, err := t.WriteTo(f); err != nil {
		log.Fatal(err)
	}
}
