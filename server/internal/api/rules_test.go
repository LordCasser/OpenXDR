package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"openxdr/server/internal/sigma"
)

type metadataCatalog struct {
	sigma.Engine
	entries []*sigma.Rule
}

func (c *metadataCatalog) Rules() []*sigma.Rule { return c.entries }
func TestTemporalRuleMetadataAndSourceCoverage(t *testing.T) {
	for _, class := range []int{1007, 999999} {
		catalog := &metadataCatalog{entries: []*sigma.Rule{
			{ID: "base", Title: "Base", ClassUID: class, Severity: 2},
			{ID: "sequence", Title: "Ordered activity", Author: "Maintainer", Severity: 4, Kind: "sequence", WindowSeconds: 60, References: []string{"base"}},
		}}
		mux := http.NewServeMux()
		mapRules(mux, catalog)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest("GET", "/api/rules", nil))
		if response.Code != 200 {
			t.Fatal(response.Code)
		}
		var rows []ruleRow
		if err := json.Unmarshal(response.Body.Bytes(), &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 {
			t.Fatal(len(rows))
		}
		row := rows[0]
		if row.ID != "sequence" || row.Kind != "sequence" || row.WindowSeconds != 60 || len(row.References) != 1 || row.Author != "Maintainer" {
			t.Fatalf("元数据丢失: %+v", row)
		}
		if row.Ingested != (class == 1007) {
			t.Fatalf("不能将缺失来源的时序规则标记为有数据: %+v", row)
		}
	}
}
