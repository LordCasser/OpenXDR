package vuln

import (
	"math"
	"strings"
)

// CVSSv3 由 3.0 / 3.1 向量算基础分；向量不完整或不是 v3 返回 0 与 false。
// OSV 里的 Debian 条目只给向量不给分，排优先级要自己算
func CVSSv3(vector string) (float64, bool) {
	parts := strings.Split(vector, "/")
	if len(parts) < 9 || !strings.HasPrefix(parts[0], "CVSS:3.") {
		return 0, false
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		if k, v, ok := strings.Cut(p, ":"); ok {
			m[k] = v
		}
	}
	weight := func(k string, table map[string]float64) (float64, bool) {
		v, ok := table[m[k]]
		return v, ok
	}
	changed := m["S"] == "C"
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if changed {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	av, ok1 := weight("AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	ac, ok2 := weight("AC", map[string]float64{"L": 0.77, "H": 0.44})
	p, ok3 := weight("PR", pr)
	ui, ok4 := weight("UI", map[string]float64{"N": 0.85, "R": 0.62})
	c, ok5 := weight("C", cia)
	i, ok6 := weight("I", cia)
	a, ok7 := weight("A", cia)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) || (m["S"] != "U" && !changed) {
		return 0, false
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	impact := 6.42 * iss
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}
	exploit := 8.22 * av * ac * p * ui
	if changed {
		return roundUp(math.Min(1.08*(impact+exploit), 10)), true
	}
	return roundUp(math.Min(impact+exploit, 10)), true
}

// roundUp CVSS 3.1 规定的向上取一位小数（避开浮点误差）
func roundUp(x float64) float64 {
	n := int64(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return float64(n/10000+1) / 10
}
