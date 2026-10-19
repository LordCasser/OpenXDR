package directory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const maxPageBytes = 2 << 20

// TokenProvider 从调用方的凭据管理器取得短期令牌，不将令牌放进来源或结果。
type TokenProvider func(context.Context) (string, error)

type Keycloak struct {
	source   Source
	endpoint string
	client   http.Client
	token    TokenProvider
}

// NewKeycloak 的 baseURL 是服务根地址，可包含 /auth；realm 是名称而非 UUID。
// 管理员配置的服务地址必须使用 HTTPS，禁止跳转携带认证信息。
func NewKeycloak(id, groupID uuid.UUID, baseURL, realm string, client *http.Client, token TokenProvider) (*Keycloak, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("Keycloak 服务地址必须为无凭据的 HTTPS 地址")
	}
	if !validText(realm, 255) || realm == "." || realm == ".." || strings.ContainsAny(realm, "/\\") || token == nil {
		return nil, fmt.Errorf("Keycloak realm 或令牌提供器无效")
	}
	root := strings.TrimRight(u.String(), "/")
	source := Source{ID: id, GroupID: groupID, Kind: "keycloak", Authority: root + "/realms/" + url.PathEscape(realm)}
	if err := source.validate(); err != nil {
		return nil, err
	}
	c := http.Client{}
	if client != nil {
		c = *client
	}
	if c.Timeout <= 0 || c.Timeout > 30*time.Second {
		c.Timeout = 30 * time.Second
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Keycloak{source: source, endpoint: root + "/admin/realms/" + url.PathEscape(realm) + "/users", client: c, token: token}, nil
}

// errInconsistent 一轮扫描里出现重复账号：偏移分页时有账号增删，前后页错位了
var errInconsistent = errors.New("Keycloak 账号在扫描期间发生变化")

// consistentAttempts 扫描期间账号持续变化时最多重扫几轮，仍不一致就拒绝，不接受残缺快照
const consistentAttempts = 3

// ReadAccounts Keycloak 只支持偏移分页，扫描中途有账号增删会让前后页错位：重复或漏掉。
// 扫描前后各取一次总数，两次相同且去重后的账号数恰好等于它，才当作一致快照；否则整轮重扫
func (k *Keycloak) ReadAccounts(ctx context.Context) (Scan, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for attempt := 1; attempt <= consistentAttempts; attempt++ {
		before, err := k.count(ctx)
		if err != nil {
			return Scan{}, err
		}
		scan, err := k.scan(ctx)
		if errors.Is(err, errInconsistent) {
			continue
		}
		if err != nil {
			return Scan{}, err
		}
		after, err := k.count(ctx)
		if err != nil {
			return Scan{}, err
		}
		if before == after && after == len(scan.Accounts) {
			return scan, nil
		}
	}
	return Scan{}, fmt.Errorf("%w，连续 %d 轮都未取得一致快照", errInconsistent, consistentAttempts)
}

func (k *Keycloak) scan(ctx context.Context) (Scan, error) {
	result := Scan{Source: k.source, StartedAt: time.Now().UTC(), Accounts: []Account{}}
	seen := make(map[string]bool)
	for page := 0; page < 1000; page++ {
		accounts, err := k.page(ctx, len(result.Accounts))
		if err != nil {
			return Scan{}, err
		}
		if len(accounts) == 0 {
			result.FinishedAt = time.Now().UTC()
			return result, nil
		}
		if len(result.Accounts)+len(accounts) > 10000 {
			return Scan{}, fmt.Errorf("Keycloak 账号枚举超过 10000 条上限")
		}
		for _, account := range accounts {
			if !validText(account.ExternalID, 1024) || !validText(account.Username, 1024) {
				return Scan{}, fmt.Errorf("Keycloak 账号标识缺失或字段无效")
			}
			if seen[account.ExternalID] {
				return Scan{}, errInconsistent
			}
			seen[account.ExternalID] = true
			result.Accounts = append(result.Accounts, account)
		}
	}
	return Scan{}, fmt.Errorf("Keycloak 账号枚举超过分页上限")
}

// count 当前账号总数
func (k *Keycloak) count(ctx context.Context) (int, error) {
	body, err := k.get(ctx, k.endpoint+"/count")
	if err != nil {
		return 0, err
	}
	var n int
	if err := json.Unmarshal(body, &n); err != nil || n < 0 || n > 10000 {
		return 0, fmt.Errorf("Keycloak 账号总数格式无效或超过 10000 条上限")
	}
	return n, nil
}

// get 带令牌请求一个管理接口，读回有界的响应体；不跟随跳转、错误里不带令牌
func (k *Keycloak) get(ctx context.Context, url string) ([]byte, error) {
	token, err := k.token(ctx)
	if err != nil {
		return nil, fmt.Errorf("Keycloak 令牌获取失败")
	}
	if !validText(token, 65536) || strings.TrimSpace(token) != token {
		return nil, fmt.Errorf("Keycloak 令牌无效")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("Keycloak 请求构造失败")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := k.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Keycloak 请求失败")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Keycloak 请求返回 HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPageBytes+1))
	if err != nil || len(body) > maxPageBytes {
		return nil, fmt.Errorf("Keycloak 响应读取失败或超过上限")
	}
	return body, nil
}

func (k *Keycloak) page(ctx context.Context, first int) ([]Account, error) {
	body, err := k.get(ctx, k.endpoint+"?first="+strconv.Itoa(first)+"&max=100&briefRepresentation=true")
	if err != nil {
		return nil, err
	}
	var users []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Enabled  *bool  `json:"enabled"`
	}
	if err := json.Unmarshal(body, &users); err != nil || users == nil || len(users) > 100 {
		return nil, fmt.Errorf("Keycloak 账号列表格式无效或超过分页上限")
	}
	accounts := make([]Account, 0, len(users))
	for _, user := range users {
		accounts = append(accounts, Account{ExternalID: user.ID, Username: user.Username, Enabled: user.Enabled})
	}
	return accounts, nil
}
