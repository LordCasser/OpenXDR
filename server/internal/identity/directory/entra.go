package directory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Entra struct {
	source Source
	root   string
	tenant uuid.UUID
	client http.Client
	token  TokenProvider
}

// NewEntra 接受管理员配置的 Graph HTTPS 根地址，支持不同云的独立端点。
// 每次枚举先读取 organization 核实租户，整次枚举使用同一个短期令牌。
func NewEntra(id, groupID, tenant uuid.UUID, graphURL string, client *http.Client, token TokenProvider) (*Entra, error) {
	u, err := url.Parse(graphURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("Entra Graph 地址必须是无凭据和路径的 HTTPS 根地址")
	}
	if tenant == uuid.Nil || token == nil {
		return nil, fmt.Errorf("Entra 租户或令牌提供器无效")
	}
	root := strings.TrimRight(u.String(), "/")
	source := Source{ID: id, GroupID: groupID, Kind: "entra", Authority: root + "/tenants/" + tenant.String()}
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
	return &Entra{source: source, root: root, tenant: tenant, client: c, token: token}, nil
}

func (e *Entra) ReadAccounts(ctx context.Context) (Scan, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	result := Scan{Source: e.source, StartedAt: time.Now().UTC(), Accounts: []Account{}}
	token, err := e.token(ctx)
	if err != nil || !validText(token, 65536) || strings.TrimSpace(token) != token {
		return Scan{}, fmt.Errorf("Entra 令牌获取失败或无效")
	}
	if err := e.verifyTenant(ctx, token); err != nil {
		return Scan{}, err
	}
	next := e.root + "/v1.0/users?$select=id,userPrincipalName,accountEnabled&$top=100"
	seenPages := make(map[string]bool)
	seenIDs := make(map[string]bool)
	for page := 0; page < 1000; page++ {
		if !e.validPageURL(next) || seenPages[next] {
			return Scan{}, fmt.Errorf("Entra 分页地址越界或重复")
		}
		seenPages[next] = true
		body, err := e.get(ctx, next, token)
		if err != nil {
			return Scan{}, err
		}
		var response struct {
			Value []struct {
				ID      string `json:"id"`
				UPN     string `json:"userPrincipalName"`
				Enabled *bool  `json:"accountEnabled"`
			} `json:"value"`
			Next string `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &response); err != nil || response.Value == nil || len(response.Value) > 100 || len(result.Accounts)+len(response.Value) > 10000 {
			return Scan{}, fmt.Errorf("Entra 账号列表格式无效或超过上限")
		}
		for _, user := range response.Value {
			id, err := uuid.Parse(user.ID)
			if err != nil || id == uuid.Nil || !validText(user.UPN, 1024) || seenIDs[id.String()] {
				return Scan{}, fmt.Errorf("Entra 账号稳定标识缺失、重复或字段无效")
			}
			seenIDs[id.String()] = true
			result.Accounts = append(result.Accounts, Account{ExternalID: id.String(), Username: user.UPN, Enabled: user.Enabled})
		}
		if response.Next == "" {
			result.FinishedAt = time.Now().UTC()
			return result, nil
		}
		next = response.Next
	}
	return Scan{}, fmt.Errorf("Entra 账号枚举超过分页上限")
}

func (e *Entra) validPageURL(value string) bool {
	if len(value) > 16384 {
		return false
	}
	u, err := url.Parse(value)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && "https://"+u.Host == e.root && u.User == nil && u.Fragment == "" && u.Opaque == "" && u.EscapedPath() == "/v1.0/users"
}

func (e *Entra) verifyTenant(ctx context.Context, token string) error {
	body, err := e.get(ctx, e.root+"/v1.0/organization?$select=id", token)
	if err != nil {
		return err
	}
	var response struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
		Next string `json:"@odata.nextLink"`
	}
	if err := json.Unmarshal(body, &response); err != nil || len(response.Value) != 1 || response.Next != "" {
		return fmt.Errorf("Entra 租户验证响应无效")
	}
	id, err := uuid.Parse(response.Value[0].ID)
	if err != nil || id != e.tenant {
		return fmt.Errorf("Entra 令牌所属租户与配置不一致")
	}
	return nil
}

func (e *Entra) get(ctx context.Context, endpoint, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("Entra 请求构造失败")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Entra 请求失败")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Entra 请求返回 HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPageBytes+1))
	if err != nil || len(body) > maxPageBytes {
		return nil, fmt.Errorf("Entra 响应读取失败或超过上限")
	}
	return body, nil
}
