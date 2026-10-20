package suppress

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"openxdr/server/ent/schema"
)

// Condition 抑制的字段条件，见 schema.SuppressCondition
type Condition = schema.SuppressCondition

// MaxConditions 一条抑制最多几个字段条件
const MaxConditions = 3

var fieldPath = regexp.MustCompile(`^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*){0,5}$`)

// Validate 校验字段条件：字段是事件体的 dot path，op 只认 equals / contains / endswith，值 1–500 字
func Validate(conds []Condition) error {
	if len(conds) > MaxConditions {
		return fmt.Errorf("字段条件最多 %d 个", MaxConditions)
	}
	for _, c := range conds {
		if !fieldPath.MatchString(c.Field) {
			return fmt.Errorf("字段 %q 不是事件体的 dot path（如 query.hostname、process.cmd_line）", c.Field)
		}
		if c.Op != "equals" && c.Op != "contains" && c.Op != "endswith" {
			return errors.New("op 只能是 equals / contains / endswith")
		}
		if n := utf8.RuneCountInString(c.Value); n == 0 || n > 500 {
			return errors.New("条件值须为 1–500 字")
		}
	}
	return nil
}

// Matches 事件体是否满足全部条件；没有条件视为满足
func Matches(conds []Condition, raw map[string]any) bool {
	for _, c := range conds {
		v, ok := Lookup(raw, c.Field)
		if !ok {
			return false
		}
		v, want := strings.ToLower(v), strings.ToLower(c.Value)
		switch c.Op {
		case "equals":
			ok = v == want
		case "contains":
			ok = strings.Contains(v, want)
		case "endswith":
			ok = strings.HasSuffix(v, want)
		default:
			ok = false
		}
		if !ok {
			return false
		}
	}
	return true
}

// Lookup 按 dot path 取事件体里的标量值；路径不存在或落在对象、数组上返回 false
func Lookup(raw map[string]any, path string) (string, bool) {
	var cur any = raw
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		if cur, ok = m[part]; !ok {
			return "", false
		}
	}
	switch v := cur.(type) {
	case nil, map[string]any, []any:
		return "", false
	case string:
		return v, true
	default:
		return fmt.Sprint(v), true
	}
}
