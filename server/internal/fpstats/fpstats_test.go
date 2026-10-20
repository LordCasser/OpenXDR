package fpstats

import (
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/suppress"
)

// 被拒的是整条规则时，同规则下更窄的按实体草案照样可以提；拒了窄的，宽的不提
func TestCovered(t *testing.T) {
	now := time.Now()
	narrow := []suppress.Condition{{Field: "file.path", Op: "equals", Value: "/a"}}
	rejected := func(conds []suppress.Condition) *ent.Suppression {
		at := now.Add(-time.Hour)
		return &ent.Suppression{Status: "rejected", ReviewedAt: &at, Conditions: conds}
	}
	if covered(rejected(nil), narrow, now, time.Hour*24) {
		t.Error("拒了整条规则不该挡住按实体的草案")
	}
	if !covered(rejected(narrow), nil, now, time.Hour*24) {
		t.Error("拒了按实体的，整条规则更不该提")
	}
	past := now.Add(-time.Minute)
	if covered(&ent.Suppression{Status: "active", ExpiresAt: &past}, narrow, now, 0) {
		t.Error("过期的抑制不算覆盖")
	}
}
