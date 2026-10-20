package temporal

import (
	"cmp"
	"fmt"
	"maps"
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
	// Asset 是事件所属资产，用于 min_assets 的不同资产计数；min_assets 大于 1 的规则要求必填。
	Asset string
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
		if r.minAssets > 1 && input.Asset == "" {
			return nil, fmt.Errorf("min_assets 规则的时序事件缺少资产")
		}
		e := input
		e.Rules = append([]string(nil), input.Rules...)
		slices.Sort(e.Rules)
		e.Rules = slices.Compact(e.Rules)
		if prior, ok := seen[e.ID]; ok {
			if prior.Scope != e.Scope || prior.Asset != e.Asset || !prior.Time.Equal(e.Time) || !slices.Equal(prior.Rules, e.Rules) {
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
			if !r.anchors(anchor) {
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
		// 只在条件恰好成立的那一条出命中（越过阈值那一刻）：持续爆破时窗口一直满足条件，
		// 每条都出命中会让每个终点都绑定告警、证据永不过期，写库次数也随窗口线性增长。
		// 条件是计数达到 threshold 且不同资产数达到 min_assets；终点之前的同窗口事件已满足则不是越过的那一刻。
		// min_assets 为 1 时等价于前序恰好 threshold-1 条。
		if r.counted(prior) || !r.counted(append(prior[:len(prior):len(prior)], anchor)) {
			return nil
		}
		return append(evidence, anchor.ID)
	}
	if r.kind == "temporal" {
		// 与计数同理只在条件越过的那一刻出命中。前序已凑齐就不是越过；凑齐时的分配必然用到终点本身。
		if r.cover(prior) != nil {
			return nil
		}
		return r.cover(append(prior[:len(prior):len(prior)], anchor))
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

// counted 判断窗口内命中基础规则的事件是否同时满足计数阈值与不同资产数。
func (r *Rule) counted(events []Event) bool {
	count := 0
	assets := map[string]bool{}
	for _, e := range events {
		if slices.Contains(e.Rules, r.references[0]) {
			count++
			assets[e.Asset] = true
		}
	}
	return count >= r.threshold && (r.minAssets <= 1 || len(assets) >= r.minAssets)
}

// anchors 判断事件能否作为终点：序列与计数只认最后一步，共现任一引用规则都可以。
func (r *Rule) anchors(e Event) bool {
	if r.kind == "temporal" {
		return slices.ContainsFunc(r.references, func(id string) bool { return slices.Contains(e.Rules, id) })
	}
	return slices.Contains(e.Rules, r.references[len(r.references)-1])
}

// cover 给每条引用规则分配一个不同的事件（二分图增广路匹配），按时间顺序返回所选事件；分配不出来返回 nil。
// 不要求先后、允许同一时刻：兄弟进程几乎同时启动，采集到的先后不可信。
// 每条规则只取最早的 len(references) 个候选：某条规则的候选达到这个数时，其余规则最多占去其中 len-1 个，
// 它总能分到一个，更多候选不会改变能否分配，也让结果只取决于时间顺序。
func (r *Rule) cover(events []Event) []uuid.UUID {
	k := len(r.references)
	options := make([][]int, k)
	for i, e := range events {
		for j, id := range r.references {
			if len(options[j]) < k && slices.Contains(e.Rules, id) {
				options[j] = append(options[j], i)
			}
		}
	}
	owner := map[int]int{} // 事件下标 -> 规则下标
	var assign func(j int, tried map[int]bool) bool
	assign = func(j int, tried map[int]bool) bool {
		for _, i := range options[j] {
			if tried[i] {
				continue
			}
			tried[i] = true
			if other, taken := owner[i]; !taken || assign(other, tried) {
				owner[i] = j
				return true
			}
		}
		return false
	}
	for j := range k {
		if !assign(j, map[int]bool{}) {
			return nil
		}
	}
	picked := slices.Sorted(maps.Keys(owner))
	evidence := make([]uuid.UUID, len(picked))
	for n, i := range picked {
		evidence[n] = events[i].ID
	}
	return evidence
}
