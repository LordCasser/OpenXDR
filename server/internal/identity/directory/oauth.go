package directory

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type OAuthConfig struct {
	TokenURL        string `json:"tokenURL"`
	ClientID        string `json:"clientId"`
	ClientSecretEnv string `json:"clientSecretEnv"`
	Scope           string `json:"scope"`
}

// NewClientCredentials 使用显式 HTTPS 令牌端点；不进行发现或跟随重定向。
// 缓存仅在当前来源实例内存在，过期前重新取令牌，不使用 refresh_token。
func NewClientCredentials(config OAuthConfig, secret func() string, client *http.Client) (TokenProvider, error) {
	u, err := url.Parse(config.TokenURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || len(config.TokenURL) > 2048 {
		return nil, fmt.Errorf("OAuth 令牌端点必须为无凭据的 HTTPS 地址")
	}
	if !validText(config.ClientID, 1024) || (config.Scope != "" && !validText(config.Scope, 2048)) || secret == nil {
		return nil, fmt.Errorf("OAuth 客户端配置无效")
	}
	c := http.Client{}
	if client != nil {
		c = *client
	}
	if c.Timeout <= 0 || c.Timeout > 30*time.Second {
		c.Timeout = 30 * time.Second
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	gate := make(chan struct{}, 1)
	var token string
	var until time.Time
	var secretHash [32]byte
	return func(ctx context.Context) (string, error) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case gate <- struct{}{}:
		}
		defer func() { <-gate }()
		if err := ctx.Err(); err != nil {
			return "", err
		}
		credential := secret()
		if credential == "" || len(credential) > 65536 {
			return "", fmt.Errorf("OAuth 客户端密钥缺失或过长")
		}
		currentHash := sha256.Sum256([]byte(credential))
		if token != "" && secretHash == currentHash && time.Now().Before(until) {
			return token, nil
		}
		// 失败不回退到旧令牌，凭据变化后旧缓存立即失效。
		token = ""
		until = time.Time{}
		started := time.Now()
		value, expires, err := fetchClientToken(ctx, &c, config, credential)
		if err != nil {
			return "", err
		}
		if !time.Now().Before(started.Add(time.Duration(expires) * time.Second)) {
			return "", fmt.Errorf("OAuth 返回令牌已过期")
		}
		// 缓存最多一小时；短有效期令牌可以用于本次请求，但不会复用。
		if expires > 3600 {
			expires = 3600
		}
		token = value
		secretHash = currentHash
		until = started.Add(time.Duration(expires-30) * time.Second)
		return token, nil
	}, nil
}

func fetchClientToken(ctx context.Context, client *http.Client, config OAuthConfig, secret string) (string, int64, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {config.ClientID}, "client_secret": {secret}}
	if config.Scope != "" {
		form.Set("scope", config.Scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("OAuth 请求构造失败")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("OAuth 令牌请求失败")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("OAuth 令牌请求返回 HTTP %d", resp.StatusCode)
	}
	const limit = 128 << 10
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || len(body) > limit {
		return "", 0, fmt.Errorf("OAuth 响应读取失败或超过上限")
	}
	var result struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &result); err != nil || !strings.EqualFold(result.TokenType, "Bearer") || !validText(result.AccessToken, 65536) || strings.ContainsAny(result.AccessToken, " \t\r\n") || result.ExpiresIn <= 0 || result.ExpiresIn > 86400*365 {
		return "", 0, fmt.Errorf("OAuth 令牌响应无效")
	}
	return result.AccessToken, result.ExpiresIn, nil
}
