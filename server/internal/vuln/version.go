// Package vuln 软件清单对漏洞库：agent 报上来已装的包与源码版本，server 从 OSV 同步发行版的漏洞公告，
// 查询时按发行版的版本规则比较，回答「这台主机有哪些已知漏洞、升级能修掉哪些、暴露在外的服务有没有」。
//
// 第一版只支持 dpkg 系（Debian、Ubuntu）：公告按源码包发布，版本比较按 dpkg 规则。
package vuln

import "strings"

// CompareDeb 按 dpkg 规则比较两个版本：[epoch:]upstream[-revision]，返回负数、零或正数
func CompareDeb(a, b string) int {
	ea, ua, ra := splitDeb(a)
	eb, ub, rb := splitDeb(b)
	if c := compareNum(ea, eb); c != 0 {
		return c
	}
	if c := compareFragment(ua, ub); c != 0 {
		return c
	}
	return compareFragment(ra, rb)
}

func splitDeb(v string) (epoch, upstream, revision string) {
	epoch = "0"
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch, v = v[:i], v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// order 非数字字符的排序：~ 比一切都小（连空串都小），字母在其余符号之前
func order(c byte) int {
	switch {
	case c == '~':
		return -1
	case c >= '0' && c <= '9':
		return 0
	case c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z':
		return int(c)
	default:
		return int(c) + 256
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// compareFragment dpkg 的 verrevcmp：非数字段逐字符比，数字段按数值比，交替进行
func compareFragment(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := 0, 0
			if i < len(a) && !isDigit(a[i]) {
				ac = order(a[i])
			}
			if j < len(b) && !isDigit(b[j]) {
				bc = order(b[j])
			}
			if ac != bc {
				return ac - bc
			}
			i++
			j++
		}
		si, sj := i, j
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		if c := compareNum(a[si:i], b[sj:j]); c != 0 {
			return c
		}
	}
	return 0
}

// compareNum 比较两段数字串，不转整数：版本号里的长数字（日期戳）会溢出
func compareNum(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return len(a) - len(b)
	}
	return strings.Compare(a, b)
}
