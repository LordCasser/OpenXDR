package temporal

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

const accountPrefix = "account:"

// AccountEntity 把事件 username 列规范化成账号维度实体：去首尾空白、转小写。
// 不做域前缀/UPN 等格式互认；空用户名返回空串，调用方必须计入 no_account 缺口而不是归到某个默认账号。
func AccountEntity(username string) string {
	name := strings.ToLower(strings.TrimSpace(username))
	if name == "" {
		return ""
	}
	return accountPrefix + name
}

// IsAccountEntity 区分账号维度实体与资产 ID。
func IsAccountEntity(entity string) bool { return strings.HasPrefix(entity, accountPrefix) }

// Scope 必须由可信入库上下文构造，不能直接采用模型或原始日志自报的归组。
// Group 及 Entity 均不可为空；没有授权归属的事件不能参与关联。
type Scope struct {
	Group  uuid.UUID
	Entity string
}
type Event struct {
	ID    uuid.UUID
	Time  time.Time
	Scope Scope
	Rules []string
}
type Match struct {
	Severity int16
	Revision string // 由完整规则快照填写；裸 Rule 求值不代表可持久化命中
	RuleID   string
	Anchor   uuid.UUID
	Time     time.Time
	Scope    Scope
	Evidence []uuid.UUID
}

// Evaluate 对完整候选窗口求值。调用者不能静默截断窗口；候选过多应显式失败。
// 返回每个满足条件的终点事件的一次命中，持久幂等键为规则版本、Scope、Anchor。
func (r *Rule) Evaluate(events []Event) ([]Match, error) {
	if r == nil || r.id == "" {
		return nil, fmt.Errorf("时序规则未编译")
	}
	if len(events) > 10000 {
		return nil, fmt.Errorf("时序候选超过 10000 条，不能截断后求值")
	}
	groups := map[Scope][]Event{}
	seen := map[uuid.UUID]Event{}
	for _, input := range events {
		if input.ID == uuid.Nil || input.Time.IsZero() || input.Scope.Group == uuid.Nil || input.Scope.Entity == "" {
			return nil, fmt.Errorf("时序事件缺少身份、时间或授权归属")
		}
		e := input
		e.Rules = append([]string(nil), input.Rules...)
		slices.Sort(e.Rules)
		e.Rules = slices.Compact(e.Rules)
		if prior, ok := seen[e.ID]; ok {
			if prior.Scope != e.Scope || !prior.Time.Equal(e.Time) || !slices.Equal(prior.Rules, e.Rules) {
				return nil, fmt.Errorf("同一事件 ID 的内容冲突: %s", e.ID)
			}
			continue
		}
		seen[e.ID] = e
		groups[e.Scope] = append(groups[e.Scope], e)
	}
	var matches []Match
	for scope, group := range groups {
		slices.SortFunc(group, compareEvent)
		for i, anchor := range group {
			if !slices.Contains(anchor.Rules, r.references[len(r.references)-1]) {
				continue
			}
			start := i
			cutoff := anchor.Time.Add(-r.window)
			for start > 0 && !group[start-1].Time.Before(cutoff) {
				start--
			}
			evidence := r.evidence(group[start:i], anchor)
			if evidence == nil {
				continue
			}
			matches = append(matches, Match{Severity: r.severity, RuleID: r.id, Anchor: anchor.ID, Time: anchor.Time, Scope: scope, Evidence: evidence})
		}
	}
	slices.SortFunc(matches, func(a, b Match) int {
		if c := a.Time.Compare(b.Time); c != 0 {
			return c
		}
		return cmp.Compare(a.Anchor.String(), b.Anchor.String())
	})
	return matches, nil
}

func compareEvent(a, b Event) int {
	if c := a.Time.Compare(b.Time); c != 0 {
		return c
	}
	return cmp.Compare(a.ID.String(), b.ID.String())
}

func (r *Rule) evidence(prior []Event, anchor Event) []uuid.UUID {
	var evidence []uuid.UUID
	if r.kind == "event_count" {
		for _, e := range prior {
			// 同时发生不能证明严格先后，但仍是不同事件；计数以 UUID 排序稳定选取终点。
			if slices.Contains(e.Rules, r.references[0]) {
				evidence = append(evidence, e.ID)
			}
		}
		// 只在窗口内计数恰好到阈值的那一条出命中：持续爆破时窗口一直在阈值之上，
		// 每条都出命中会让每个终点都绑定告警、证据永不过期，写库次数也随窗口线性增长
		if len(evidence) != r.threshold-1 {
			return nil
		}
		return append(evidence, anchor.ID)
	}
	step := 0
	var previous time.Time
	for _, e := range prior {
		if !e.Time.Before(anchor.Time) || (!previous.IsZero() && !e.Time.After(previous)) {
			continue
		}
		if !slices.Contains(e.Rules, r.references[step]) {
			continue
		}
		evidence = append(evidence, e.ID)
		previous = e.Time
		step++
		if step == len(r.references)-1 {
			return append(evidence, anchor.ID)
		}
	}
	return nil
}
