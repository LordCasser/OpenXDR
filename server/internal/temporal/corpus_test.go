package temporal

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

// 回放事件原文，不能直接在语料里伪造基础规则命中。到达顺序和事件时间各自保留。
func TestRepositoryTemporalCorpus(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	snapshot, err := LoadSnapshot(filepath.Join(root, "rules"), filepath.Join(root, "temporal-rules"))
	if err != nil {
		t.Fatal(err)
	}
	type expected struct {
		Rule     string   `json:"rule"`
		Anchor   string   `json:"anchor"`
		Evidence []string `json:"evidence"`
	}
	var cases []struct {
		Name   string `json:"name"`
		Events []struct {
			ID       string         `json:"id"`
			Seconds  int            `json:"seconds"`
			Group    string         `json:"group"`
			Asset    string         `json:"asset"`
			OS       string         `json:"os"`
			ClassUID int            `json:"classUid"`
			Raw      map[string]any `json:"raw"`
		} `json:"events"`
		Matches []expected `json:"matches"`
	}
	f, err := os.Open(filepath.Join(root, "validation", "temporal", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cases); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatal("语料有尾随内容")
	}
	if len(cases) == 0 {
		t.Fatal("时序语料不能为空")
	}
	id := func(value string) uuid.UUID { return uuid.NewSHA1(uuid.NameSpaceOID, []byte(value)) }
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Name == "" || len(tc.Events) == 0 {
				t.Fatal("用例名称和事件不能为空")
			}
			current := snapshot
			var events []Event
			got := map[string][]uuid.UUID{}
			// 每个新到达事件触发窗口求值，模拟首次命中记账；不把本测试当作数据库幂等证明。
			for i, input := range tc.Events {
				if input.ID == "" || input.Group == "" || input.Asset == "" || input.OS == "" || input.ClassUID == 0 || input.Raw == nil {
					t.Fatal("语料缺少事件身份、范围或原文")
				}
				if i == len(tc.Events)/2 {
					current, err = RestoreArchive(snapshot.Archive())
					if err != nil {
						t.Fatal(err)
					}
				}
				refs := current.CandidateRules(current.EvaluateBase(input.ClassUID, input.OS, input.Raw))
				if len(refs) == 0 {
					continue
				}
				events = append(events, Event{ID: id(input.ID), Time: time.Unix(1700000000+int64(input.Seconds), 0).UTC(), Scope: Scope{Group: id(input.Group), Entity: input.Asset}, Rules: refs})
				matches, err := current.Evaluate(events)
				if err != nil {
					t.Fatal(err)
				}
				for _, m := range matches {
					key := m.RuleID + "/" + m.Anchor.String()
					if _, exists := got[key]; !exists {
						got[key] = m.Evidence
					}
				}
			}
			want := map[string][]uuid.UUID{}
			for _, m := range tc.Matches {
				var evidence []uuid.UUID
				for _, v := range m.Evidence {
					evidence = append(evidence, id(v))
				}
				want[m.Rule+"/"+id(m.Anchor).String()] = evidence
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("时序回放不符合预期\n实际: %v\n预期: %v", got, want)
			}
		})
	}
}
