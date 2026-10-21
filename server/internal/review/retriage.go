package review

import (
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"

	"openxdr/server/ent"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/predicate"
)

// 重研判口径：研判、通知、自动结案与界面共用。
// status=open 表示还没有可用结论，等首次研判；已研判（triaged）的事件再并入新证据时不改状态，
// 关联引擎记下 evidence_at（升级类另记 urgent_at），晚于 triaged_at 就是结论之后又有没看过的证据。
// 旧研判没有 triaged_at，按「从未研判」比较：有新证据就算待重研判，拿不准不当作已看过。

// newer 某个时刻列晚于上次研判
func newer(col string) predicate.Incident {
	return func(s *sql.Selector) {
		// 列为空时整体为假而不是 NULL，套 NOT 才不会把没证据的行一并排除
		s.Where(sql.ExprP(fmt.Sprintf("%[1]s IS NOT NULL AND %[1]s > COALESCE(%[2]s, '-infinity')", s.C(col), s.C(incident.FieldTriagedAt))))
	}
}

// Retriage 已研判、之后又并入了新证据：旧结论仍可用，冷却到期后重研判
func Retriage() predicate.Incident {
	return incident.And(incident.StatusEQ("triaged"), newer(incident.FieldEvidenceAt))
}

// Urgent 已研判、之后又并入了升级类证据：旧结论不作数，立即重研判，通知等新结论
func Urgent() predicate.Incident {
	return incident.And(incident.StatusEQ("triaged"), newer(incident.FieldUrgentAt))
}

// IsRetriage 与 Retriage 同一口径，给已加载的行用
func IsRetriage(inc *ent.Incident) bool {
	return inc.Status == "triaged" && after(inc.EvidenceAt, inc.TriagedAt)
}

// IsUrgent 与 Urgent 同一口径
func IsUrgent(inc *ent.Incident) bool {
	return inc.Status == "triaged" && after(inc.UrgentAt, inc.TriagedAt)
}

func after(t, triaged *time.Time) bool {
	return t != nil && (triaged == nil || t.After(*triaged))
}
