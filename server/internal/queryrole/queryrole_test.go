package queryrole

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// 平台账号只有 CREATEROLE、不是超级用户：PostgreSQL 16 起这些属性连 NO 的写法都会被拒，整个开通事务回滚。
// 集成测试用超级用户跑，测不出来，这里直接看语句
func TestDDLAvoidsSuperuserOnlyAttributes(t *testing.T) {
	for _, stmt := range ddl(uuid.New(), "p", true) {
		if !strings.HasPrefix(stmt, "ALTER ROLE") && !strings.Contains(stmt, "CREATE ROLE") {
			continue
		}
		for _, attr := range []string{"SUPERUSER", "REPLICATION", "BYPASSRLS", "CREATEDB"} {
			if strings.Contains(stmt, attr) {
				t.Errorf("非超级用户执行不了含 %s 的角色语句：%s", attr, stmt)
			}
		}
	}
}
