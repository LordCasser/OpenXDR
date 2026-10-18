package agentchat

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/commandgate"
)

// 沙箱原型：会话外的 Pi（默认 bash/read/write 工具，跑在没有任何平台密钥的隔离容器里）
// 经 xdr 命令行调用本会话的工具。身份、组、名单审批与审计和会话内的 Pi 完全相同，只是换了入口。

const (
	sandboxTokenTTL = 4 * time.Hour
	// 沙箱调用经反向代理，审批不能一直挂着：等不到就告诉模型仍在等待
	sandboxApprovalWait = 2 * time.Minute
	sandboxKeyPrefix    = "sandbox:"
)

var sandboxTools = []string{"exec", "query", "track", "identify", "report"}

type sandboxGrant struct {
	Session uuid.UUID `json:"session"`
	User    uuid.UUID `json:"user"`
	Expires time.Time `json:"expires"`
}

func sandboxKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return sandboxKeyPrefix + hex.EncodeToString(sum[:])
}

// IssueSandboxToken 给会话发起人签发工具令牌。只存哈希，多节点共用同一张表
func (s *Service) IssueSandboxToken(ctx context.Context, session *ent.AgentSession, u *ent.User) (string, time.Time, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", time.Time{}, err
	}
	token := hex.EncodeToString(buf)
	grant := sandboxGrant{Session: session.ID, User: u.ID, Expires: time.Now().Add(sandboxTokenTTL)}
	value, _ := json.Marshal(grant)
	if err := s.DB.Setting.Create().SetID(sandboxKey(token)).SetValue(value).Exec(ctx); err != nil {
		return "", time.Time{}, err
	}
	return token, grant.Expires, nil
}

var errSandboxToken = errors.New("工具令牌无效或已过期")

// SandboxCall 凭令牌调用一次工具；context 返回平台本该放进系统提示的组内数据
func (s *Service) SandboxCall(ctx context.Context, token, name string, args json.RawMessage) (string, error) {
	row, err := s.DB.Setting.Get(ctx, sandboxKey(token))
	if err != nil {
		return "", errSandboxToken
	}
	var grant sandboxGrant
	if json.Unmarshal(row.Value, &grant) != nil || time.Now().After(grant.Expires) {
		return "", errSandboxToken
	}
	session, err := s.DB.AgentSession.Get(ctx, grant.Session)
	if err != nil {
		return "", errSandboxToken
	}
	u, err := s.DB.User.Get(ctx, grant.User)
	if err != nil {
		return "", errSandboxToken
	}
	// 每次都按当前角色复核：签发后被降权或移出组，令牌随之失效
	if !auth.Allowed(auth.GroupRole(ctx, s.DB, u, session.GroupID), "analyst") {
		return "", errors.New("已无本组分析权限")
	}
	if name == "context" {
		data, _, _, err := s.contextData(ctx, session)
		if err != nil {
			return "", err
		}
		return marshal(data)
	}
	if !slices.Contains(sandboxTools, name) {
		return "", errors.New("未知工具")
	}
	return s.tool(ctx, session, commandgate.Request{UserID: u.ID, ApprovalTimeout: sandboxApprovalWait}, name, args)
}

// IsSandboxTokenError 令牌问题与工具执行错误分开报，前者给 401
func IsSandboxTokenError(err error) bool { return errors.Is(err, errSandboxToken) }
