package suppress

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

var (
	fixNow   = time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	fixAsset = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	otherAS  = uuid.MustParse("22222222-2222-2222-2222-222222222222")
)

func ptr[T any](v T) *T { return &v }

func TestMatchRule(t *testing.T) {
	expired := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC) // 早于 fixNow
	valid := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)   // 晚于 fixNow
	idA := uuid.New()
	idB := uuid.New()
	idC := uuid.New()

	cases := []struct {
		name    string
		entries []entry
		assetID *uuid.UUID
		want    *uuid.UUID
	}{
		{name: "无规则返回 nil", entries: nil, want: nil},
		{name: "空切片返回 nil", entries: []entry{}, want: nil},
		{
			name:    "全局规则任意资产命中",
			entries: []entry{{id: idA, expires: &valid}},
			assetID: ptr(fixAsset),
			want:    ptr(idA),
		},
		{
			name:    "全局规则空资产命中",
			entries: []entry{{id: idA, expires: &valid}},
			assetID: nil,
			want:    ptr(idA),
		},
		{
			name:    "限定资产匹配命中",
			entries: []entry{{id: idA, assetID: ptr(fixAsset), expires: &valid}},
			assetID: ptr(fixAsset),
			want:    ptr(idA),
		},
		{
			name:    "限定资产不匹配跳过",
			entries: []entry{{id: idA, assetID: ptr(fixAsset), expires: &valid}},
			assetID: ptr(otherAS),
			want:    nil,
		},
		{
			name:    "限定资产遇空资产跳过",
			entries: []entry{{id: idA, assetID: ptr(fixAsset), expires: &valid}},
			assetID: nil,
			want:    nil,
		},
		{
			name:    "过期规则跳过",
			entries: []entry{{id: idA, expires: &expired}},
			assetID: nil,
			want:    nil,
		},
		{
			name: "第一条过期第二条命中取第二条",
			entries: []entry{
				{id: idA, expires: &expired},
				{id: idC, assetID: ptr(fixAsset), expires: &valid},
			},
			assetID: ptr(fixAsset),
			want:    ptr(idC),
		},
		{
			name: "既过期又不匹配全部跳过",
			entries: []entry{
				{id: idA, assetID: ptr(otherAS), expires: &valid},
				{id: idB, expires: &expired},
			},
			assetID: ptr(fixAsset),
			want:    nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := matchRule(tc.entries, tc.assetID, nil, fixNow)
			if !sameID(got, tc.want) {
				t.Fatalf("matchRule() = %v, want %v", got, tc.want)
			}
		})
	}
}

func sameID(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// TestSuppressedHit 验证命中时返回 true 并累加计数，不命中不计数。
func TestSuppressedHit(t *testing.T) {
	id := uuid.New()
	now := fixNow

	s := &Store{
		byRule: map[string][]entry{
			"r1": {{id: id, expires: ptr(now.Add(time.Hour))}},
			"r2": {{id: uuid.New(), assetID: ptr(otherAS), expires: ptr(now.Add(time.Hour))}},
		},
		counters: map[uuid.UUID]*counter{},
	}

	if !s.Suppressed("r1", ptr(fixAsset), nil, now) {
		t.Fatal("r1 应命中")
	}
	if !s.Suppressed("r1", nil, nil, now.Add(time.Second)) {
		t.Fatal("r1 第二次应命中")
	}
	if s.Suppressed("r2", ptr(fixAsset), nil, now) {
		t.Fatal("r2 限定资产不匹配应不命中")
	}
	if s.Suppressed("不存在", ptr(fixAsset), nil, now) {
		t.Fatal("无规则应不命中")
	}

	s.mu.RLock()
	c := s.counters[id]
	s.mu.RUnlock()
	if c == nil {
		t.Fatal("命中应记录计数器")
	}
	if c.hits != 2 {
		t.Fatalf("hits = %d, want 2", c.hits)
	}
	if !c.last.Equal(now.Add(time.Second)) {
		t.Fatalf("last = %v, want %v", c.last, now.Add(time.Second))
	}
}

// 字段条件：只压掉字段对得上的命中，同规则别的命中照常告警；条件校验拒绝乱写的字段与操作符
func TestConditions(t *testing.T) {
	asset := ptr(fixAsset)
	e := []entry{{id: uuid.New(), assetID: asset, conds: []Condition{{Field: "query.hostname", Op: "endswith", Value: ".DOGGYGO.top"}}}}
	hit := map[string]any{"query": map[string]any{"hostname": "4mrf9fwf.doggygo.top"}}
	other := map[string]any{"query": map[string]any{"hostname": "evil.top"}}
	if matchRule(e, asset, hit, fixNow) == nil {
		t.Error("域名对得上应抑制（不区分大小写）")
	}
	if matchRule(e, asset, other, fixNow) != nil || matchRule(e, asset, nil, fixNow) != nil {
		t.Error("别的域名或缺字段不应抑制")
	}
	port := []entry{{id: uuid.New(), conds: []Condition{{Field: "dst_endpoint.port", Op: "equals", Value: "22"}, {Field: "process.cmd_line", Op: "contains", Value: "__termix"}}}}
	if matchRule(port, nil, map[string]any{"dst_endpoint": map[string]any{"port": 22.0}, "process": map[string]any{"cmd_line": "bash -c __TERMIX_EXIT"}}, fixNow) == nil {
		t.Error("数字字段与多条件 AND 应生效")
	}
	for _, bad := range [][]Condition{
		{{Field: "Query.Hostname", Op: "equals", Value: "x"}},
		{{Field: "query.hostname", Op: "regex", Value: "x"}},
		{{Field: "query.hostname", Op: "equals", Value: ""}},
		{{Field: "a", Op: "equals", Value: "1"}, {Field: "b", Op: "equals", Value: "1"}, {Field: "c", Op: "equals", Value: "1"}, {Field: "d", Op: "equals", Value: "1"}},
	} {
		if Validate(bad) == nil {
			t.Errorf("应拒绝: %+v", bad)
		}
	}
}
