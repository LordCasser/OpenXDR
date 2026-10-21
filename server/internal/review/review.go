// Package review "需要人看"的统一口径：通知推送、待复核计数与列表、良性事件自动结案共用一套定义，
// 改一处全跟着变，不会出现总览说要看、通知却没推的情况。
package review

import (
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"

	"openxdr/server/ent/alert"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/predicate"
	"openxdr/server/internal/decoy"
)

// Severity 及以上的事件即使 AI 判良性也要人复核：AI 会看错，高危被一句"良性"吞掉代价太大
const Severity = 4

// ClosedBy 系统自动结案的 resolved_by，用来和分析师的人工结论区分
const ClosedBy = "system"

// unresolved 引擎已研判但分析师还没结案的也算未结案
func unresolved() predicate.Incident { return incident.StatusIn("open", "triaged") }

// benign AI 结论为良性；没有结论或结论缺字段都不算良性
func benign() predicate.Incident {
	return func(s *sql.Selector) {
		s.Where(sql.ExprP(fmt.Sprintf("COALESCE(%s->>'verdict', '') = 'benign'", s.C(incident.FieldAiVerdict))))
	}
}

func severe() predicate.Incident { return incident.HasAlertsWith(alert.SeverityGTE(Severity)) }

func decoyAlert() predicate.Alert { return alert.RuleIDHasPrefix(decoy.ObservationRulePrefix) }

// decoyReview 含分析师提交的诱饵观察：人点名要复核，AI 判良性也不能替人结案。
func decoyReview() predicate.Incident { return incident.HasAlertsWith(decoyAlert()) }

// DecoyOnly 只有诱饵观察：按约定只做站内复核不推送；同主机真实告警并入后照常通知。
func DecoyOnly() predicate.Incident {
	return incident.And(decoyReview(), incident.Not(incident.HasAlertsWith(alert.Not(decoyAlert()))))
}

// Needed 未结案，且 AI 没判良性、最高级别达到 Severity 或含人工提交的诱饵观察。
func Needed() predicate.Incident {
	return incident.And(unresolved(), incident.Or(incident.Not(benign()), severe(), decoyReview()))
}

// StaleBenign 已研判、AI 判良性、级别低于 Severity 且创建早于 before：没人看也不必看的噪声。
// 良性结论之后又并入了新证据（待重研判）或分析师重开（open）的不算：旧结论没看过新证据，不能拿它结案
func StaleBenign(before time.Time) predicate.Incident {
	return incident.And(incident.StatusEQ("triaged"), incident.Not(newer(incident.FieldEvidenceAt)),
		benign(), incident.Not(severe()), incident.Not(decoyReview()), incident.CreatedAtLT(before))
}
