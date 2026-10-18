package piruntime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// Remote 远端沙箱（sandboxd）：一条全双工 HTTP 流，请求体是 runner 的 stdin，响应体是 stdout
type Remote struct {
	URL    string
	Key    string
	Client *http.Client
}

// NewRemote 地址为 https 时可指定自签 CA；明文地址只适合受信网络调试
func NewRemote(url, key, caFile string) (*Remote, error) {
	url = strings.TrimRight(url, "/")
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return nil, errors.New("SANDBOX_URL 必须是 http(s) 地址")
	}
	if len(key) < 32 {
		return nil, errors.New("SANDBOX_KEY 必须配置且不少于 32 个字符")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// 沙箱在内网，不走 HTTP_PROXY
	transport.Proxy = nil
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("SANDBOX_CA_FILE 不含有效证书")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &Remote{URL: url, Key: key, Client: &http.Client{Transport: transport}}, nil
}

func (r *Remote) open(ctx context.Context) (*channel, error) {
	in, out := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL+"/run", in)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+r.Key)
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := r.Client.Do(req)
	if err != nil {
		_ = out.Close()
		return nil, fmt.Errorf("连接沙箱失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		_ = out.Close()
		return nil, fmt.Errorf("沙箱拒绝运行: %s %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return &channel{out, resp.Body, func() error { return nil }}, nil
}
