package grpcsvc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// 构造带指定 CN 客户端证书的 peer 上下文，免去真实 TLS 握手。
func ctxWithCN(cn string) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{
					{Subject: pkix.Name{CommonName: cn}},
				}},
			},
		},
	})
}

func TestCertHostname(t *testing.T) {
	cases := []struct {
		name  string
		ctx   context.Context
		host  string
		bound bool
	}{
		{"绑定证书", ctxWithCN("host:web01"), "web01", true},
		{"探针证书不是 agent 身份", ctxWithCN("sensor:web01"), "", false},
		{"通用证书不受限", ctxWithCN("openxdr-collector"), "", false},
		{"明文连接不受限", context.Background(), "", false},
	}
	for _, c := range cases {
		host, bound := certHostname(c.ctx)
		if bound != c.bound || (bound && host != c.host) {
			t.Errorf("%s: want (%q,%v) got (%q,%v)", c.name, c.host, c.bound, host, bound)
		}
	}
	if host, ok := sensorHostname(ctxWithCN("sensor:gw01")); !ok || host != "gw01" {
		t.Errorf("探针证书应绑定 gw01，got (%q,%v)", host, ok)
	}
	if _, ok := sensorHostname(ctxWithCN("host:gw01")); ok {
		t.Error("agent 证书不是探针身份")
	}
}

// 证书用途与服务交叉：探针证书进不了 agent 通道，agent 证书进不了探针通道，通用证书两边都能进。
func TestCheckService(t *testing.T) {
	agent := "/openxdr.agent.v1.AgentService/Commands"
	sensor := "/openxdr.sensor.v1.SensorService/ReportFlows"
	cases := []struct {
		cn, method string
		ok         bool
	}{
		{"host:web01", agent, true},
		{"host:web01", sensor, false},
		{"sensor:gw01", sensor, true},
		{"sensor:gw01", agent, false},
		{"openxdr-collector", agent, true},
		{"openxdr-collector", sensor, true},
	}
	for _, c := range cases {
		if err := checkService(ctxWithCN(c.cn), c.method); (err == nil) != c.ok {
			t.Errorf("%s 访问 %s：want ok=%v got %v", c.cn, c.method, c.ok, err)
		}
	}
	if err := checkService(context.Background(), agent); err != nil {
		t.Errorf("明文连接不在这里拦：%v", err)
	}
}
