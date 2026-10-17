// Package assetmap 资产图谱与攻击面：把 agent 上报的设备清单（监听端口、云环境）
// 和网络事件里的连接物化成资产画像与依赖边，按区域算出暴露面，并让 AI 标注
// 每台资产的角色、功能与重要程度。事实全部来自确定性采集，AI 只做解读。
package assetmap

import (
	"cmp"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"unicode"
)

// ClassInventory OCSF Device Inventory Info：agent 的监听端口与云环境快照
const ClassInventory = 5001

// classNetwork OCSF Network Activity：agent 出站连接与 sensor 会话
const classNetwork = 4001

const maxListeners = 512

// Listener 一个监听中的套接字。Process 取不到时为空。
type Listener struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	PID     int    `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
	Path    string `json:"path,omitempty"`
}

// Loopback 只绑在回环地址上，外面连不进来
func (l Listener) Loopback() bool {
	a, err := netip.ParseAddr(l.Addr)
	return err == nil && a.Unmap().IsLoopback()
}

// Cloud agent 从云厂商元数据服务读到的实例信息
type Cloud struct {
	Provider   string `json:"provider"`
	InstanceID string `json:"instanceId"`
	Region     string `json:"region,omitempty"`
	PublicIP   string `json:"publicIp,omitempty"`
}

var providers = []string{"aws", "azure", "gcp", "aliyun", "tencent"}

// inventory 从 5001 事件体解出监听端口与云环境。agent 数据不可信：
// 字段逐个校验，坏条目丢弃，云信息缺关键字段就当不在云上。
func inventory(raw json.RawMessage) ([]Listener, *Cloud) {
	var body struct {
		Device struct {
			Listening []struct {
				Proto   string `json:"proto"`
				Addr    string `json:"addr"`
				Port    int    `json:"port"`
				Process *struct {
					PID  int    `json:"pid"`
					Name string `json:"name"`
					File *struct {
						Path string `json:"path"`
					} `json:"file"`
				} `json:"process"`
			} `json:"listening"`
			Cloud *struct {
				Provider   string `json:"provider"`
				InstanceID string `json:"instance_id"`
				Region     string `json:"region"`
				PublicIP   string `json:"public_ip"`
			} `json:"cloud"`
		} `json:"device"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return nil, nil
	}
	type key struct {
		proto, addr string
		port        int
	}
	seen := map[key]bool{}
	var out []Listener
	for _, l := range body.Device.Listening {
		addr, err := netip.ParseAddr(l.Addr)
		if (l.Proto != "tcp" && l.Proto != "udp") || err != nil || l.Port < 1 || l.Port > 65535 {
			continue
		}
		e := Listener{Proto: l.Proto, Addr: addr.String(), Port: l.Port}
		if p := l.Process; p != nil {
			e.PID, e.Process = p.PID, clean(p.Name, 64)
			if p.File != nil {
				e.Path = clean(p.File.Path, 256)
			}
		}
		k := key{e.Proto, e.Addr, e.Port}
		if seen[k] || len(out) == maxListeners {
			continue
		}
		seen[k] = true
		out = append(out, e)
	}
	slices.SortFunc(out, func(a, b Listener) int {
		return cmp.Or(strings.Compare(a.Proto, b.Proto), cmp.Compare(a.Port, b.Port), strings.Compare(a.Addr, b.Addr))
	})

	var cloud *Cloud
	if c := body.Device.Cloud; c != nil && slices.Contains(providers, c.Provider) && clean(c.InstanceID, 128) != "" {
		cloud = &Cloud{Provider: c.Provider, InstanceID: clean(c.InstanceID, 128), Region: clean(c.Region, 64)}
		if ip, err := netip.ParseAddr(c.PublicIP); err == nil {
			cloud.PublicIP = ip.String()
		}
	}
	return out, cloud
}

// clean 去掉不可打印字符并截断，模型和页面都会看到这些字符串
func clean(s string, max int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s))
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return s
}
