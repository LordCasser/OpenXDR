package correlate

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/incident"
	"openxdr/server/internal/sigma"
)

// 复发归并时每次最多比对的候选告警数：同资产同规则的未结案告警通常只有几条，
// 超出说明这条规则在这台机器上命中的实体五花八门，比不到就新建 incident，不会错并
const recurCandidates = 100

var errNoRecurrence = errors.New("无可归并的复发")

// recurKeys 复发归并的实体键：同一资产、同一规则下，什么算「同一件事又来了」。
// 情报规则的 rule_id 本身带着 IOC（intel:ip:1.2.3.4），规则相同即实体相同；
// 其余按事件类别取关键实体：域名、文件路径、网络对端 IP；进程取执行用户、父进程映像、映像与完整命令行。
// 容器是独立主机（PVE 上的 LXC），一并入键。取不到实体返回空串——拿不准就不并。
// coarse 是进程类告警更粗一档的键（见 coarseKey），其余类别为空。
func recurKeys(al *ent.Alert) (exact, coarse string) {
	evt := al.Edges.Event
	if evt == nil {
		return "", ""
	}
	var raw struct {
		Container struct {
			UID  string `json:"uid"`
			Name string `json:"name"`
		} `json:"container"`
		Query struct {
			Hostname string `json:"hostname"`
		} `json:"query"`
		File struct {
			Path string `json:"path"`
		} `json:"file"`
		Process struct {
			CmdLine string `json:"cmd_line"`
			File    struct {
				Path string `json:"path"`
			} `json:"file"`
			Parent struct {
				File struct {
					Path string `json:"path"`
				} `json:"file"`
			} `json:"parent_process"`
		} `json:"process"`
		Conn struct {
			Direction string `json:"direction"`
		} `json:"connection_info"`
		Src struct {
			IP string `json:"ip"`
		} `json:"src_endpoint"`
		Dst struct {
			IP string `json:"ip"`
		} `json:"dst_endpoint"`
	}
	if json.Unmarshal(evt.Raw, &raw) != nil {
		return "", ""
	}

	entity := ""
	switch {
	case strings.HasPrefix(al.RuleID, "intel:"):
		entity = "ioc"
	case evt.ClassUID == classDNSActivity:
		entity = strings.ToLower(raw.Query.Hostname)
	case evt.ClassUID == classNetworkActivity:
		// agent 入站时 src 是对端；出站与 sensor 会话（src 摆正为客户端，资产按源 IP 归属）对端在 dst
		entity = raw.Dst.IP
		if raw.Conn.Direction == "inbound" {
			entity = raw.Src.IP
		}
	case evt.ClassUID == classFileActivity:
		entity = raw.File.Path
	case evt.ClassUID == classProcessActivity && raw.Process.File.Path+raw.Process.CmdLine != "":
		// 谁拉起的、以谁的身份：同一条命令换个用户或换个父进程，不是同一件事
		who := ""
		if evt.Username != nil {
			who = *evt.Username
		}
		who += "|" + normPath(raw.Process.Parent.File.Path) + "|"
		entity = who + normPath(raw.Process.File.Path) + "\x00" + raw.Process.CmdLine
		coarse = coarseKey(al.RuleID, who, raw.Process.File.Path)
	}
	if entity == "" {
		return "", ""
	}
	container := raw.Container.UID + "|" + raw.Container.Name + "|"
	if coarse != "" {
		coarse = container + coarse
	}
	return container + entity, coarse
}

// coarseKey 进程类告警的粗键：精确键去掉命令行，即执行用户 + 父进程映像 + 进程映像——
// 同一程序由同一种父进程以同一用户反复拉起，参数不同（lvcreate 换个卷、pgrep 换个名字）仍是同一类事。
// 映像是解释器或命令包装器时不给粗键：bash -c 后面跟什么都行，映像相同说明不了行为相同，只按完整命令行认。
// 首次出现（xdr:new-process）按（资产, 映像）建基线，同一映像只告警一次，映像入键永远并不上；
// 它的粗键去掉映像：同一主机同一用户同一父进程下陆续冒出的新程序并成一件事看。
func coarseKey(ruleID, who, image string) string {
	if image == "" || interpreter(image) {
		return ""
	}
	if ruleID == sigma.RuleNewProcess {
		return who
	}
	return who + normPath(image)
}

// interpreters 解释器与命令包装器：执行的是参数里的任意代码，按映像归类会把不同行为并到一起。
// 名单外的程序参数不同仍按同一类处理；后缀版本号（python3.12、perl5.36）与 .exe 去掉再比。
var interpreters = map[string]bool{
	// shell
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "mksh": true, "ash": true,
	"fish": true, "csh": true, "tcsh": true, "busybox": true,
	// 脚本语言
	"python": true, "perl": true, "ruby": true, "node": true, "php": true, "lua": true,
	"tclsh": true, "awk": true, "gawk": true, "mawk": true, "nawk": true,
	// Windows 脚本宿主与代理执行
	"powershell": true, "pwsh": true, "cmd": true, "wscript": true, "cscript": true, "mshta": true,
	"rundll32": true, "regsvr32": true, "msiexec": true, "wmic": true,
	// 命令包装器：后面跟的命令才是行为
	"env": true, "timeout": true, "nohup": true, "sudo": true, "su": true, "doas": true, "runuser": true,
	"setsid": true, "xargs": true, "nice": true, "ionice": true, "stdbuf": true, "chroot": true,
	"nsenter": true, "unshare": true, "flock": true, "watch": true, "script": true, "time": true,
	"ssh": true,
}

func interpreter(image string) bool {
	name := strings.ToLower(image[strings.LastIndexAny(image, `/\`)+1:])
	name = strings.TrimRight(strings.TrimSuffix(name, ".exe"), "0123456789.")
	return interpreters[name]
}

// normPath 同一程序的不同写法归一：merged-usr 下 /bin、/sbin、/lib 是 /usr 下的链接；Windows 路径不分大小写
func normPath(p string) string {
	if len(p) > 1 && p[1] == ':' {
		return strings.ToLower(p)
	}
	for _, dir := range []string{"/bin/", "/sbin/", "/lib/", "/lib64/"} {
		if strings.HasPrefix(p, dir) {
			return "/usr" + p
		}
	}
	return p
}

// findRecurrence 同资产、同规则、同实体的告警已在未结案 incident 里，且该 incident
// 起始不早于 RecurSpan：周期性的扫描、轮询是同一件事反复发生，并回去而不是每次新开。
// 已结案的不重开——分析师的结论针对的是当时的证据，复发另起一个 incident 重新看。
// coarse 非空时粗键相同也算：进程类同映像同用户同父进程的告警，命令行不同也并（见 coarseKey）。
func (e *Engine) findRecurrence(ctx context.Context, al *ent.Alert, key, coarse string) (*ent.Incident, error) {
	if e.RecurSpan <= 0 || al.AssetID == nil || key == "" {
		return nil, errNoRecurrence
	}
	prior, err := e.DB.Alert.Query().
		Where(
			alert.AssetIDEQ(*al.AssetID),
			alert.RuleIDEQ(al.RuleID),
			alert.HasIncidentWith(
				incident.StatusIn("open", "triaged"),
				incident.CreatedAtGTE(al.Ts.Add(-e.RecurSpan)),
			),
		).
		Order(ent.Desc(alert.FieldTs)).
		Limit(recurCandidates).
		WithEvent().
		WithIncident().
		All(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range prior {
		if k, c := recurKeys(p); k == key || (coarse != "" && c == coarse) {
			return p.Edges.Incident, nil
		}
	}
	return nil, errNoRecurrence
}

// seenIn incident 里是否已有同资产、同规则、同实体的告警：有就不算新证据。
// 只认精确键：粗键并进来的是同类的另一件事（命令行不同、新冒出的程序），要重新研判。
func (e *Engine) seenIn(ctx context.Context, incID uuid.UUID, al *ent.Alert, key string) bool {
	if al.AssetID == nil || key == "" {
		return false
	}
	prior, err := e.DB.Alert.Query().
		Where(alert.IncidentIDEQ(incID), alert.AssetIDEQ(*al.AssetID), alert.RuleIDEQ(al.RuleID)).
		Order(ent.Desc(alert.FieldTs)).
		Limit(recurCandidates).
		WithEvent().
		All(ctx)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(prior, func(p *ent.Alert) bool {
		k, _ := recurKeys(p)
		return k == key
	})
}
