package temporal

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

func rule(t *testing.T, kind, refs string, threshold int) *Rule {
	t.Helper()
	extra := ""
	if threshold != 0 {
		extra = fmt.Sprintf("threshold: %d\n", threshold)
	}
	r, err := Compile([]byte("id: test\nkind: "+kind+"\nwithin: 10m\nrules: ["+refs+"]\n"+extra), map[string]bool{"a": true, "b": true, "c": true})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func event(n int, seconds int, rules ...string) Event {
	return Event{ID: uuid.MustParse(fmt.Sprintf("00000000-0000-4000-8000-%012d", n)), Time: time.Unix(1700000000+int64(seconds), 0), Scope: Scope{Group: uuid.MustParse("10000000-0000-4000-8000-000000000001"), Entity: "host:user"}, Rules: rules}
}

func TestCountWindowDedupAndScope(t *testing.T) {
	r := rule(t, "event_count", "a", 3)
	cases := []struct {
		name   string
		events []Event
		want   int
	}{
		{"三次", []Event{event(1, 0, "a"), event(2, 1, "a"), event(3, 2, "a")}, 1},
		{"重复不凑数", []Event{event(1, 0, "a"), event(1, 0, "a"), event(2, 1, "a")}, 0},
		{"同时间不同事件", []Event{event(3, 0, "a"), event(1, 0, "a"), event(2, 0, "a")}, 1},
		{"包含窗口下界", []Event{event(1, 0, "a"), event(2, 300, "a"), event(3, 600, "a")}, 1},
		{"窗口之外", []Event{event(1, 0, "a"), event(2, 300, "a"), event(3, 601, "a")}, 0},
		// 持续超过阈值只在越过时出一次；计数掉回阈值以下再越过才出第二次
		{"持续爆破只命中一次", []Event{event(1, 0, "a"), event(2, 1, "a"), event(3, 2, "a"), event(4, 3, "a"), event(5, 4, "a"), event(6, 5, "a")}, 1},
		{"回落后再越过", []Event{event(1, 0, "a"), event(2, 1, "a"), event(3, 2, "a"), event(4, 1000, "a"), event(5, 1001, "a"), event(6, 1002, "a")}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := r.Evaluate(tc.events)
			if err != nil || len(m) != tc.want {
				t.Fatalf("%+v %v", m, err)
			}
		})
	}
	for _, dimension := range []string{"group", "entity"} {
		events := []Event{event(1, 0, "a"), event(2, 1, "a"), event(3, 2, "a")}
		if dimension == "group" {
			events[2].Scope.Group = uuid.New()
		} else {
			events[2].Scope.Entity = "another"
		}
		m, err := r.Evaluate(events)
		if err != nil || len(m) != 0 {
			t.Fatalf("跨 %s 关联: %+v %v", dimension, m, err)
		}
	}
}

func TestSequenceStrictOrderAndEvidence(t *testing.T) {
	r := rule(t, "sequence", "a,b,c", 0)
	for _, tc := range []struct {
		name   string
		events []Event
		want   int
	}{
		{"乱序到达", []Event{event(3, 600, "c"), event(1, 0, "a"), event(2, 2, "b")}, 1},
		{"相同时间无顺序", []Event{event(1, 0, "a"), event(2, 0, "b"), event(3, 1, "c")}, 0},
		{"一条不能占两步", []Event{event(1, 0, "a", "b"), event(3, 1, "c")}, 0},
		{"顺序相反", []Event{event(1, 0, "b"), event(2, 1, "a"), event(3, 2, "c")}, 0},
		{"窗口之外", []Event{event(1, 0, "a"), event(2, 1, "b"), event(3, 601, "c")}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := r.Evaluate(tc.events)
			if err != nil || len(m) != tc.want {
				t.Fatalf("%+v %v", m, err)
			}
			if len(m) > 0 && !reflect.DeepEqual(m[0].Evidence, []uuid.UUID{event(1, 0).ID, event(2, 0).ID, event(3, 0).ID}) {
				t.Fatalf("证据顺序错误: %+v", m)
			}
		})
	}
	// 重复规则引用必须消费不同时间的事件，允许 a -> a -> b。
	repeated := rule(t, "sequence", "a,a,b", 0)
	m, err := repeated.Evaluate([]Event{event(1, 0, "a"), event(2, 1, "a"), event(3, 2, "b")})
	if err != nil || len(m) != 1 {
		t.Fatalf("重复步骤失败: %+v %v", m, err)
	}
}

func TestReorderingAndReplayAreDeterministic(t *testing.T) {
	for _, r := range []*Rule{rule(t, "sequence", "a,b,c", 0), rule(t, "event_count", "a", 3)} {
		events := []Event{event(1, 0, "a"), event(2, 1, "a", "b"), event(3, 2, "a", "b"), event(4, 3, "c"), event(5, 4, "c")}
		want, err := r.Evaluate(events)
		if err != nil {
			t.Fatal(err)
		}
		rng := rand.New(rand.NewSource(42))
		for i := 0; i < 50; i++ {
			input := append(append([]Event(nil), events...), events...)
			rng.Shuffle(len(input), func(i, j int) { input[i], input[j] = input[j], input[i] })
			got, err := r.Evaluate(input)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("重排改变结果: %+v / %+v (%v)", got, want, err)
			}
		}
	}
}

func TestInvalidIdentityAndConflictingReplay(t *testing.T) {
	r := rule(t, "event_count", "a", 2)
	for _, mutate := range []func(*Event){func(e *Event) { e.Time = e.Time.Add(time.Second) }, func(e *Event) { e.Scope.Entity = "other" }, func(e *Event) { e.Rules = []string{"b"} }} {
		a := event(1, 0, "a")
		b := a
		mutate(&b)
		if _, err := r.Evaluate([]Event{a, b}); err == nil {
			t.Fatal("同 ID 冲突必须拒绝")
		}
	}
	a := event(1, 0, "a")
	a.Scope.Group = uuid.Nil
	if _, err := r.Evaluate([]Event{a}); err == nil {
		t.Fatal("空授权归属必须拒绝")
	}
	if _, err := r.Evaluate(make([]Event, 10001)); err == nil {
		t.Fatal("超限不能静默截断")
	}
}

func TestCompileRejectsUnsupportedDefinitions(t *testing.T) {
	for _, text := range []string{
		"id: x\nkind: sequence\nwithin: 1m\nrules: [a,b]\nunknown: true",
		"id: x\nkind: event_count\nwithin: 1m\nrules: [missing]\nthreshold: 3",
		"id: x\nkind: sequence\nwithin: 1m\nrules: [a,b]\nthreshold: 3",
		"id: x\nkind: event_count\nwithin: 0s\nrules: [a]\nthreshold: 3",
		"id: x\nkind: sequence\nwithin: 1m\nrules: [a,b]\n---\nid: second",
		"id: a\nkind: event_count\nwithin: 1m\nrules: [a]\nthreshold: 3",
	} {
		if _, err := Compile([]byte(text), map[string]bool{"a": true, "b": true}); err == nil {
			t.Fatalf("应拒绝: %s", text)
		}
	}
}

func TestSeverityConfiguration(t *testing.T) {
	for level, want := range map[string]int16{"": 3, "informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5} {
		text := "id: x\nkind: event_count\nwithin: 1m\nrules: [a]\nthreshold: 2\n"
		if level != "" {
			text += "level: " + level + "\n"
		}
		r, err := Compile([]byte(text), map[string]bool{"a": true})
		if err != nil {
			t.Fatal(err)
		}
		matches, err := r.Evaluate([]Event{event(1, 0, "a"), event(2, 1, "a")})
		if err != nil || len(matches) != 1 || matches[0].Severity != want {
			t.Fatalf("level=%q: %+v %v", level, matches, err)
		}
	}
	if _, err := Compile([]byte("id: x\nkind: sequence\nwithin: 1m\nrules: [a,a]\nlevel: typo\n"), map[string]bool{"a": true}); err == nil {
		t.Fatal("非法等级不能静默回退")
	}
}

func TestGroupByConfiguration(t *testing.T) {
	refs := map[string]bool{"a": true}
	for value, want := range map[string]string{"": GroupByAsset, "asset": GroupByAsset, "account": GroupByAccount} {
		text := "id: x\nkind: event_count\nwithin: 1m\nrules: [a]\nthreshold: 2\n"
		if value != "" {
			text += "group_by: " + value + "\n"
		}
		r, err := Compile([]byte(text), refs)
		if err != nil || r.groupBy != want {
			t.Fatalf("group_by=%q: %v %v", value, r, err)
		}
	}
	for _, value := range []string{"user", "Account", "host", "[asset]"} {
		if _, err := Compile([]byte("id: x\nkind: event_count\nwithin: 1m\nrules: [a]\nthreshold: 2\ngroup_by: "+value+"\n"), refs); err == nil {
			t.Fatalf("未知 group_by 必须拒绝: %s", value)
		}
	}
}

func TestAccountEntityNormalization(t *testing.T) {
	if AccountEntity("  Admin ") != AccountEntity("admin") || AccountEntity("admin") == "" {
		t.Fatal("同一账号大小写/空白不同应归为同一实体")
	}
	if AccountEntity("") != "" || AccountEntity("   ") != "" {
		t.Fatal("空用户名不能归到某个默认账号")
	}
	if AccountEntity(`CORP\admin`) == AccountEntity("admin") {
		t.Fatal("不做域前缀互认")
	}
	if !IsAccountEntity(AccountEntity("admin")) || IsAccountEntity(uuid.NewString()) {
		t.Fatal("账号实体与资产 ID 必须可区分")
	}
}

// 快照只用对应维度的规则求值，资产维度候选不会被账号规则误用，反之亦然。
func TestSnapshotEvaluatesByDimension(t *testing.T) {
	asset, err := Compile([]byte("id: by-asset\nkind: event_count\nwithin: 1m\nrules: [a]\nthreshold: 2\n"), map[string]bool{"a": true})
	if err != nil {
		t.Fatal(err)
	}
	account, err := Compile([]byte("id: by-account\nkind: event_count\nwithin: 1m\nrules: [a]\nthreshold: 3\ngroup_by: account\n"), map[string]bool{"a": true})
	if err != nil {
		t.Fatal(err)
	}
	s := &Snapshot{rules: []*Rule{asset, account}, revision: "r"}
	events := []Event{event(1, 0, "a"), event(2, 1, "a"), event(3, 2, "a")}
	for groupBy, want := range map[string]string{GroupByAsset: "by-asset", GroupByAccount: "by-account"} {
		matches, err := s.Evaluate(groupBy, events)
		if err != nil || len(matches) != 1 || matches[0].RuleID != want || matches[0].Revision != "r" {
			t.Fatalf("%s: %+v %v", groupBy, matches, err)
		}
		if !s.Relevant(groupBy, []string{"a"}) || s.Relevant(groupBy, []string{"b"}) {
			t.Fatalf("%s 维度相关性判断错误", groupBy)
		}
	}
}
