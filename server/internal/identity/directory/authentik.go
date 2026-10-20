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

// authentikTypes 已知账号类型及是否为服务账号；未知类型无法判定过滤口径，整轮拒绝
var authentikTypes = map[string]bool{
	"internal":                 false,
	"external":                 false,
	"service_account":          true,
	"internal_service_account": true,
}

type Authentik struct {
	source   Source
	endpoint string
	services bool
	client   http.Client
	token    TokenProvider
}

// NewAuthentik 的 baseURL 是实例根地址；services 为 false 时只保留人类用户。
// 只调用 GET，不跟随跳转，令牌只放在请求头。
func NewAuthentik(id, groupID uuid.UUID, baseURL string, services bool, client *http.Client, token TokenProvider) (*Authentik, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("Authentik 服务地址必须为无凭据的 HTTPS 地址")
	}
	if token == nil {
		return nil, fmt.Errorf("Authentik 令牌提供器无效")
	}
	root := strings.TrimRight(u.String(), "/")
	source := Source{ID: id, GroupID: groupID, Kind: "authentik", Authority: root}
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
	return &Authentik{source: source, endpoint: root + "/api/v3/core/users/", services: services, client: c, token: token}, nil
}

var errAuthentikInconsistent = errors.New("Authentik 账号在扫描期间发生变化")

type authentikUser struct {
	account Account
	service bool
}

// ReadAccounts 页码分页同样会因扫描中途增删错位。每轮前后各取一次总数，
// 两次相同、每页自报总数一致且去重后的账号数恰好等于它，才当作一致快照；否则整轮重扫。
// 总数包含服务账号，所以一致性校验在过滤之前做。
func (a *Authentik) ReadAccounts(ctx context.Context) (Scan, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for attempt := 1; attempt <= consistentAttempts; attempt++ {
		before, err := a.count(ctx)
		if err != nil {
			return Scan{}, err
		}
		started := time.Now().UTC()
		users, err := a.scan(ctx, before)
		if errors.Is(err, errAuthentikInconsistent) {
			continue
		}
		if err != nil {
			return Scan{}, err
		}
		after, err := a.count(ctx)
		if err != nil {
			return Scan{}, err
		}
		if before != after || after != len(users) {
			continue
		}
		result := Scan{Source: a.source, StartedAt: started, FinishedAt: time.Now().UTC(), Accounts: []Account{}}
		for _, user := range users {
			if a.services || !user.service {
				result.Accounts = append(result.Accounts, user.account)
			}
		}
		return result, nil
	}
	return Scan{}, fmt.Errorf("%w，连续 %d 轮都未取得一致快照", errAuthentikInconsistent, consistentAttempts)
}

func (a *Authentik) scan(ctx context.Context, total int) ([]authentikUser, error) {
	users := []authentikUser{}
	seen := make(map[string]bool)
	for page := 1; page <= 1000; page++ {
		response, err := a.page(ctx, page, 100)
		if err != nil {
			return nil, err
		}
		if response.Pagination.Count != total {
			return nil, errAuthentikInconsistent
		}
		if len(users)+len(response.Results) > 10000 {
			return nil, fmt.Errorf("Authentik 账号枚举超过 10000 条上限")
		}
		for _, raw := range response.Results {
			user, err := raw.user()
			if err != nil {
				return nil, err
			}
			if seen[user.account.ExternalID] {
				return nil, errAuthentikInconsistent
			}
			seen[user.account.ExternalID] = true
			users = append(users, user)
		}
		if response.Pagination.Next == 0 {
			return users, nil
		}
		if response.Pagination.Next != page+1 {
			return nil, fmt.Errorf("Authentik 分页序号无效")
		}
	}
	return nil, fmt.Errorf("Authentik 账号枚举超过分页上限")
}

// count 当前账号总数（含服务账号），取一条记录的页即可
func (a *Authentik) count(ctx context.Context) (int, error) {
	response, err := a.page(ctx, 1, 1)
	if err != nil {
		return 0, err
	}
	if response.Pagination.Count > 10000 {
		return 0, fmt.Errorf("Authentik 账号总数超过 10000 条上限")
	}
	return response.Pagination.Count, nil
}

type authentikPage struct {
	Pagination *struct {
		Next    int `json:"next"`
		Current int `json:"current"`
		Count   int `json:"count"`
	} `json:"pagination"`
	Results []authentikRaw `json:"results"`
}

type authentikRaw struct {
	UUID     string `json:"uuid"`
	Username string `json:"username"`
	IsActive *bool  `json:"is_active"`
	Type     string `json:"type"`
}

// user 以 uuid 为不可变外部 ID；pk 与 username 都不参与身份
func (r authentikRaw) user() (authentikUser, error) {
	id, err := uuid.Parse(r.UUID)
	if err != nil || id == uuid.Nil || !validText(r.Username, 1024) {
		return authentikUser{}, fmt.Errorf("Authentik 账号标识缺失或字段无效")
	}
	service, known := authentikTypes[r.Type]
	if !known {
		return authentikUser{}, fmt.Errorf("Authentik 账号类型未知")
	}
	return authentikUser{account: Account{ExternalID: id.String(), Username: r.Username, Enabled: r.IsActive}, service: service}, nil
}

func (a *Authentik) page(ctx context.Context, page, size int) (authentikPage, error) {
	body, err := a.get(ctx, a.endpoint+"?page="+strconv.Itoa(page)+"&page_size="+strconv.Itoa(size))
	if err != nil {
		return authentikPage{}, err
	}
	var response authentikPage
	if err := json.Unmarshal(body, &response); err != nil || response.Pagination == nil || response.Results == nil ||
		len(response.Results) > size || response.Pagination.Current != page || response.Pagination.Count < 0 || response.Pagination.Next < 0 {
		return authentikPage{}, fmt.Errorf("Authentik 账号列表格式无效或超过分页上限")
	}
	return response, nil
}

// get 带令牌请求只读接口，读回有界的响应体；不跟随跳转、错误里不带令牌或响应体
func (a *Authentik) get(ctx context.Context, endpoint string) ([]byte, error) {
	token, err := a.token(ctx)
	if err != nil {
		return nil, fmt.Errorf("Authentik 令牌获取失败")
	}
	if !validText(token, 65536) || strings.TrimSpace(token) != token {
		return nil, fmt.Errorf("Authentik 令牌无效")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("Authentik 请求构造失败")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Authentik 请求失败")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Authentik 请求返回 HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPageBytes+1))
	if err != nil || len(body) > maxPageBytes {
		return nil, fmt.Errorf("Authentik 响应读取失败或超过上限")
	}
	return body, nil
}
