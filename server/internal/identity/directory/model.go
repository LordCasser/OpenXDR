// Package directory 定义目录来源内的账号观察，不按同名或邮箱跨来源合并。
package directory

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

type Source struct {
	ID        uuid.UUID `json:"id"`
	GroupID   uuid.UUID `json:"groupId"`
	Kind      string    `json:"kind"`
	Authority string    `json:"authority"`
}

type Account struct {
	WindowsSID string `json:"windowsSid,omitempty"`
	ExternalID string `json:"externalId"`
	Username   string `json:"username"`
	Enabled    *bool  `json:"enabled"`
}

// Scan 是一次有界枚举，不是事务快照。账号缺席不构成删除或停用证据。
// Enabled 为 nil 表示来源没有提供状态，不能用 false 补齐。
type Scan struct {
	Source     Source    `json:"source"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	Accounts   []Account `json:"accounts"`
}

type Reader interface {
	ReadAccounts(context.Context) (Scan, error)
}

func (s Source) validate() error {
	if s.ID == uuid.Nil || s.GroupID == uuid.Nil || !validText(s.Kind, 64) || !validText(s.Authority, 2048) {
		return fmt.Errorf("目录来源标识、归组或权威地址无效")
	}
	return nil
}

// AccountID 使用来源和归组命名空间；显示名变更不改变身份。
func (s Source) AccountID(externalID string) (uuid.UUID, error) {
	if err := s.validate(); err != nil {
		return uuid.Nil, err
	}
	if !validText(externalID, 1024) {
		return uuid.Nil, fmt.Errorf("目录账号稳定标识无效")
	}
	namespace := uuid.NewSHA1(s.GroupID, []byte(s.ID.String()+"\x00"+s.Kind+"\x00"+s.Authority))
	return uuid.NewSHA1(namespace, []byte(externalID)), nil
}

func validText(value string, limit int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= limit && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}
