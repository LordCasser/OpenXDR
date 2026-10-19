package agentchat

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"openxdr/server/ent/sessionmessage"
)

// errOverBudget 本组模型用量到了上限。和停止一样不算会话的错：会话回到 idle，额度回落后接着发送即可
var errOverBudget = errors.New("模型用量已到上限")

// groupTokens 本组近 24 小时 Pi 会话用掉的输入加输出 token，与用量页「用量最多的会话」同一口径
func (s *Service) groupTokens(ctx context.Context, groupID uuid.UUID) (int, error) {
	return s.DB.SessionMessage.Query().
		Where(sessionmessage.RoleEQ("assistant"), sessionmessage.CreatedAtGT(time.Now().Add(-24*time.Hour)),
			func(sel *sql.Selector) {
				sel.Where(sql.In(sel.C(sessionmessage.FieldSessionID),
					sql.Select("id").From(sql.Table("agent_sessions")).Where(sql.EQ("group_id", groupID))))
			}).
		Aggregate(func(sel *sql.Selector) string {
			c := sel.C(sessionmessage.FieldContent)
			return fmt.Sprintf("COALESCE(SUM(COALESCE((%s->'usage'->>'input')::bigint, 0) + COALESCE((%s->'usage'->>'output')::bigint, 0)), 0)", c, c)
		}).Int(ctx)
}

// checkBudget 本组用量到了 GroupDailyTokens 就不再调用模型；0 表示不限
func (s *Service) checkBudget(ctx context.Context, groupID uuid.UUID) error {
	if s.GroupDailyTokens <= 0 {
		return nil
	}
	used, err := s.groupTokens(ctx, groupID)
	if err != nil {
		return err
	}
	if used >= s.GroupDailyTokens {
		return fmt.Errorf("%w：本组近 24 小时用了 %d token，上限 %d（PI_GROUP_DAILY_TOKENS），稍后再试或请管理员调高", errOverBudget, used, s.GroupDailyTokens)
	}
	return nil
}
