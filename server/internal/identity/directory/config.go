package directory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Job struct {
	Source   Source
	Reader   Reader
	Interval time.Duration
}

type sourceConfig struct {
	ID              uuid.UUID    `json:"id"`
	GroupID         uuid.UUID    `json:"groupId"`
	Kind            string       `json:"kind"`
	URL             string       `json:"url"`
	Realm           string       `json:"realm"`
	TenantID        uuid.UUID    `json:"tenantId"`
	BaseDN          string       `json:"baseDN"`
	Filter          string       `json:"filter"`
	TokenEnv        string       `json:"tokenEnv"`
	OAuth           *OAuthConfig `json:"oauth"`
	BindUserEnv     string       `json:"bindUserEnv"`
	BindPasswordEnv string       `json:"bindPasswordEnv"`
	CAEnv           string       `json:"caEnv"`
	IntervalSeconds int          `json:"intervalSeconds"`
}

var envName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)

// LoadConfig 只解析受信任的启动环境配置，不访问目录。凭据只允许环境变量引用。
func LoadConfig(raw string, getenv func(string) string) ([]Job, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	if len(raw) > 65536 || getenv == nil {
		return nil, fmt.Errorf("目录配置超过上限或环境读取器缺失")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var configs []sourceConfig
	if err := decoder.Decode(&configs); err != nil || configs == nil || len(configs) > 32 {
		return nil, fmt.Errorf("目录配置必须为最多 32 项的严格 JSON 数组")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("目录配置存在尾随内容")
	}
	jobs := make([]Job, 0, len(configs))
	seen := map[uuid.UUID]bool{}
	for i, config := range configs {
		if seen[config.ID] {
			return nil, fmt.Errorf("目录配置第 %d 项来源 ID 重复", i+1)
		}
		seen[config.ID] = true
		job, err := config.job(getenv)
		if err != nil {
			return nil, fmt.Errorf("目录配置第 %d 项无效：%w", i+1, err)
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

func (c sourceConfig) job(getenv func(string) string) (Job, error) {
	interval := c.IntervalSeconds
	if interval == 0 {
		interval = 900
	}
	if interval < 300 || interval > 86400 {
		return Job{}, fmt.Errorf("同步周期须为 300–86400 秒")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAEnv != "" {
		if !envName.MatchString(c.CAEnv) {
			return Job{}, fmt.Errorf("CA 环境变量引用无效")
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		pem := getenv(c.CAEnv)
		if len(pem) > 1<<20 || !pool.AppendCertsFromPEM([]byte(pem)) {
			return Job{}, fmt.Errorf("目录 CA 配置无效")
		}
		tlsConfig.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	job := Job{Interval: time.Duration(interval) * time.Second}
	switch c.Kind {
	case "keycloak", "entra":
		if c.BaseDN != "" || c.Filter != "" || c.BindUserEnv != "" || c.BindPasswordEnv != "" {
			return Job{}, fmt.Errorf("HTTP 目录不能包含 LDAP 配置")
		}
		token, err := c.tokenProvider(getenv, client)
		if err != nil {
			return Job{}, err
		}
		if c.Kind == "keycloak" {
			if c.TenantID != uuid.Nil {
				return Job{}, fmt.Errorf("Keycloak 不接受 tenantId")
			}
			r, err := NewKeycloak(c.ID, c.GroupID, c.URL, c.Realm, client, token)
			if err != nil {
				return Job{}, err
			}
			job.Source, job.Reader = r.source, r
		} else {
			if c.Realm != "" {
				return Job{}, fmt.Errorf("Entra 不接受 realm")
			}
			r, err := NewEntra(c.ID, c.GroupID, c.TenantID, c.URL, client, token)
			if err != nil {
				return Job{}, err
			}
			job.Source, job.Reader = r.source, r
		}
	case "ad", "ldap":
		if c.Realm != "" || c.TenantID != uuid.Nil || c.TokenEnv != "" || c.OAuth != nil {
			return Job{}, fmt.Errorf("LDAP 目录不能包含 HTTP 目录配置")
		}
		if !envName.MatchString(c.BindUserEnv) || !envName.MatchString(c.BindPasswordEnv) || strings.TrimSpace(getenv(c.BindUserEnv)) == "" || getenv(c.BindPasswordEnv) == "" {
			return Job{}, fmt.Errorf("LDAP 凭据环境变量缺失或引用无效")
		}
		credentials := func(context.Context) (LDAPCredentials, error) {
			return LDAPCredentials{Username: getenv(c.BindUserEnv), Password: getenv(c.BindPasswordEnv)}, nil
		}
		r, err := NewLDAP(c.ID, c.GroupID, LDAPConfig{URL: c.URL, BaseDN: c.BaseDN, Profile: c.Kind, Filter: c.Filter}, tlsConfig, credentials)
		if err != nil {
			return Job{}, err
		}
		job.Source, job.Reader = r.source, r
	default:
		return Job{}, fmt.Errorf("目录类型不支持")
	}
	return job, nil
}

func (c sourceConfig) tokenProvider(getenv func(string) string, client *http.Client) (TokenProvider, error) {
	if c.OAuth != nil {
		if c.TokenEnv != "" {
			return nil, fmt.Errorf("OAuth 与静态令牌不能同时配置")
		}
		if !envName.MatchString(c.OAuth.ClientSecretEnv) || getenv(c.OAuth.ClientSecretEnv) == "" {
			return nil, fmt.Errorf("OAuth 客户端密钥环境变量缺失或引用无效")
		}
		if c.Kind == "entra" && strings.TrimSpace(c.OAuth.Scope) == "" {
			return nil, fmt.Errorf("Entra OAuth 必须配置资源 scope")
		}
		return NewClientCredentials(*c.OAuth, func() string { return getenv(c.OAuth.ClientSecretEnv) }, client)
	}
	if !envName.MatchString(c.TokenEnv) || strings.TrimSpace(getenv(c.TokenEnv)) == "" {
		return nil, fmt.Errorf("目录令牌环境变量缺失或引用无效")
	}
	return func(context.Context) (string, error) { return getenv(c.TokenEnv), nil }, nil
}
