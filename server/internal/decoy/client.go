package decoy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Client struct {
	base, token string
	http        *http.Client
	id          string
	instance    string
	leaseMu     sync.Mutex
	leaseState  string
}

func NewClient(base, id, token string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("平台地址必须为独立 HTTP(S) origin")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && ip != nil && ip.IsLoopback()) {
		return nil, fmt.Errorf("平台连接要求 HTTPS；仅回环地址允许 HTTP")
	}
	if _, err = uuid.Parse(id); err != nil {
		return nil, fmt.Errorf("布放 ID 无效")
	}
	if len(token) != 64 || strings.Trim(token, "0123456789abcdef") != "" {
		return nil, fmt.Errorf("布放令牌无效")
	}
	return &Client{base: strings.TrimSuffix(base, "/"), id: id, token: token, instance: uuid.NewString(), http: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 2, ResponseHeaderTimeout: 5 * time.Second}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) call(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	r, err := http.NewRequestWithContext(ctx, method, c.base+"/api/decoy-runtime/"+c.id+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", "Bearer "+c.token)
	r.Header.Set("X-Decoy-Instance", c.instance)
	r.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(r)
	if err != nil {
		return nil, ErrUnreachable
	}
	defer res.Body.Close()
	if res.StatusCode != 200 && res.StatusCode != 204 {
		return nil, StatusError(res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 8193))
	if err != nil || len(data) > 8192 {
		return nil, fmt.Errorf("平台响应无效")
	}
	return data, nil
}

var ErrUnreachable = errors.New("平台连接失败")

// StatusError 是平台给出的明确应答；4xx 表示撤销、过期或租约失效。
type StatusError int

func (e StatusError) Error() string { return fmt.Sprintf("平台拒绝请求，状态码 %d", int(e)) }

// Transient 只认网络不通与 5xx；配置无效、4xx 等明确结论都不算暂时故障。
func Transient(err error) bool {
	var status StatusError
	return errors.Is(err, ErrUnreachable) || errors.As(err, &status) && status >= 500
}

func (c *Client) Manifest(ctx context.Context) (Manifest, error) {
	var m Manifest
	data, err := c.call(ctx, "GET", "/config", nil)
	if err != nil {
		return m, err
	}
	if err = json.Unmarshal(data, &m); err != nil {
		return m, err
	}
	p, err := Lookup(m.Kind, m.Profile)
	if err != nil || m.ID != c.id || p.Template != m.Template || len(m.Marker) != 64 || strings.Trim(m.Marker, "0123456789abcdef") != "" {
		return Manifest{}, fmt.Errorf("平台布放配置无效或模板版本不匹配")
	}
	return m, nil
}
func (c *Client) Record(ctx context.Context, kind string) error {
	body, _ := json.Marshal(Observation{ID: uuid.NewString(), Kind: kind})
	// 保留同一 ID；提交后连接丢失时重试不会重复入库。
	var err error
	for range 2 {
		if _, err = c.call(ctx, "POST", "/events", body); err == nil {
			return nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return err
}
