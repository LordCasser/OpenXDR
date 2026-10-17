package assetmap

import "strconv"

// Service 端口对应的常见服务与风险档：high 远程管理、数据库、未授权高发的服务；
// medium 常见但需要关注的管理与基础服务；其余 low。只看端口不看协议内容，是猜测，页面上如实标注。
type Service struct {
	Name     string `json:"name"`
	Category string `json:"category"` // remote / database / container / share / web / infra / other
	Risk     string `json:"risk"`     // high / medium / low
}

var services = map[string]Service{
	"tcp/21":    {"FTP", "share", "high"},
	"tcp/22":    {"SSH", "remote", "medium"},
	"tcp/23":    {"Telnet", "remote", "high"},
	"tcp/25":    {"SMTP", "infra", "low"},
	"tcp/53":    {"DNS", "infra", "medium"},
	"udp/53":    {"DNS", "infra", "medium"},
	"tcp/80":    {"HTTP", "web", "low"},
	"tcp/111":   {"rpcbind", "share", "high"},
	"udp/111":   {"rpcbind", "share", "high"},
	"tcp/135":   {"MS-RPC", "remote", "high"},
	"tcp/139":   {"NetBIOS", "share", "high"},
	"udp/161":   {"SNMP", "infra", "high"},
	"tcp/389":   {"LDAP", "infra", "medium"},
	"tcp/443":   {"HTTPS", "web", "low"},
	"tcp/445":   {"SMB", "share", "high"},
	"tcp/636":   {"LDAPS", "infra", "medium"},
	"tcp/873":   {"rsync", "share", "high"},
	"tcp/1433":  {"SQL Server", "database", "high"},
	"tcp/1521":  {"Oracle", "database", "high"},
	"tcp/2049":  {"NFS", "share", "high"},
	"tcp/2375":  {"Docker API", "container", "high"},
	"tcp/2376":  {"Docker API (TLS)", "container", "medium"},
	"tcp/2379":  {"etcd", "container", "high"},
	"tcp/3000":  {"Grafana", "web", "medium"},
	"tcp/3306":  {"MySQL", "database", "high"},
	"tcp/3389":  {"RDP", "remote", "high"},
	"tcp/4222":  {"NATS", "infra", "medium"},
	"tcp/5432":  {"PostgreSQL", "database", "high"},
	"tcp/5601":  {"Kibana", "web", "medium"},
	"tcp/5900":  {"VNC", "remote", "high"},
	"tcp/5985":  {"WinRM", "remote", "high"},
	"tcp/5986":  {"WinRM (TLS)", "remote", "high"},
	"tcp/6379":  {"Redis", "database", "high"},
	"tcp/6443":  {"Kubernetes API", "container", "high"},
	"tcp/8006":  {"Proxmox VE", "remote", "high"},
	"tcp/8080":  {"HTTP-alt", "web", "medium"},
	"tcp/8443":  {"HTTPS-alt", "web", "medium"},
	"tcp/9090":  {"Prometheus", "web", "medium"},
	"tcp/9200":  {"Elasticsearch", "database", "high"},
	"tcp/10250": {"kubelet", "container", "high"},
	"tcp/11211": {"Memcached", "database", "high"},
	"udp/11211": {"Memcached", "database", "high"},
	"tcp/27017": {"MongoDB", "database", "high"},
}

// ServiceOf 未登记的端口给空名、other、low：不认识的端口不夸大
func ServiceOf(proto string, port int) Service {
	if s, ok := services[proto+"/"+strconv.Itoa(port)]; ok {
		return s
	}
	return Service{Category: "other", Risk: "low"}
}
