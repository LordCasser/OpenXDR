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
)

// 复发归并时每次最多比对的候选告警数：同资产同规则的未结案告警通常只有几条，
// 超出说明这条规则在这台机器上命中的实体五花八门，比不到就新建 incident，不会错并
const recurCandidates = 100

var errNoRecurrence = errors.New("无可归并的复发")

// recurKey 复发归并的实体键：同一资产、同一规则下，什么算「同一件事又来了」。
// 情报规则的 rule_id 本身带着 IOC（intel:ip:1.2.3.4），规则相同即实体相同；
// 其余按事件类别取关键实体：域名、文件路径、进程映像与命令行、网络对端 IP。
// 容器是独立主机（PVE 上的 LXC），一并入键。取不到实体返回空串——拿不准就不并。
func recurKey(al *ent.Alert) string {
	evt := al.Edges.Event
	if evt == nil {
		return ""
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
		return ""
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
		entity = raw.Process.File.Path + "\x00" + raw.Process.CmdLine
	}
	if entity == "" {
		return ""
	}
	return raw.Container.UID + "|" + raw.Container.Name + "|" + entity
}

// findRecurrence 同资产、同规则、同实体的告警已在未结案 incident 里，且该 incident
// 起始不早于 RecurSpan：周期性的扫描、轮询是同一件事反复发生，并回去而不是每次新开。
// 已结案的不重开——分析师的结论针对的是当时的证据，复发另起一个 incident 重新看。
func (e *Engine) findRecurrence(ctx context.Context, al *ent.Alert, key string) (*ent.Incident, error) {
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
		if recurKey(p) == key {
			return p.Edges.Incident, nil
		}
	}
	return nil, errNoRecurrence
}

// seenIn incident 里是否已有同资产、同规则、同实体的告警：有就不算新证据。
func (e *Engine) seenIn(ctx context.Context, incID uuid.UUID, al *ent.Alert, key string) bool {
	if al.AssetID == nil || key == "" {
		return false
	}
	prior, err := e.DB.Alert.Query().
		Where(alert.IncidentIDEQ(incID), alert.AssetIDEQ(*al.AssetID), alert.RuleIDEQ(al.RuleID)).
		Limit(recurCandidates).
		WithEvent().
		All(ctx)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(prior, func(p *ent.Alert) bool { return recurKey(p) == key })
}
