//go:build integration

package enroll

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/testdb"
)

// 令牌分用途：探针令牌签出 sensor: 证书，agent 令牌签不出探针证书，反之亦然；
// 同一台主机可以先后接入 agent 与探针，在线探针不能被重签。
func TestEnrollSensorKind(t *testing.T) {
	ctx, client := testdb.New(t)
	caFile, keyFile := testCA(t)
	t.Setenv("TLS_CA_FILE", caFile)
	t.Setenv("TLS_CA_KEY_FILE", keyFile)
	t.Setenv("ENROLL_GRPC_URL", "https://xdr:8081")
	s, err := FromEnv(client, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	g := client.Group.Create().SetName("edge").SaveX(ctx)
	agentToken, _, _ := s.Issue(ctx, g.ID, "admin", time.Hour)
	sensorToken, row, err := s.IssueKind(ctx, KindSensor, g.ID, "admin", time.Hour)
	if err != nil || row.Kind != "sensor" {
		t.Fatalf("应签出探针令牌：%v %+v", err, row)
	}
	if _, _, err := s.IssueKind(ctx, "root", g.ID, "admin", time.Hour); err == nil {
		t.Fatal("未知用途应拒绝")
	}
	cn := func(grant Grant) string {
		block, _ := pem.Decode([]byte(grant.Cert))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return cert.Subject.CommonName
	}

	if _, _, err := s.Enroll(ctx, agentToken, Request{Hostname: "gw01", Kind: KindSensor, CSR: csr(t, "x")}); !errors.Is(err, ErrKind) {
		t.Fatalf("agent 令牌不能接入探针：%v", err)
	}
	if _, _, err := s.Enroll(ctx, sensorToken, Request{Hostname: "gw01", CSR: csr(t, "x")}); !errors.Is(err, ErrKind) {
		t.Fatalf("探针令牌不能接入 agent（旧请求不带 kind 按 agent）：%v", err)
	}
	a, grant, err := s.Enroll(ctx, sensorToken, Request{Hostname: "gw01", OS: "linux", Kind: KindSensor, CSR: csr(t, "host:gw01")})
	if err != nil {
		t.Fatal(err)
	}
	if got := cn(grant); got != "sensor:gw01" || *a.GroupID != g.ID {
		t.Fatalf("探针证书 CN 应为 sensor:gw01 并入组：%q", got)
	}
	// 同一台主机再接 agent：同一条资产，证书是 host:
	b, grant, err := s.Enroll(ctx, agentToken, Request{Hostname: "gw01", OS: "linux", CSR: csr(t, "sensor:gw01")})
	if err != nil || b.ID != a.ID || cn(grant) != "host:gw01" {
		t.Fatalf("同机 agent 应接入同一资产、证书 host:gw01：%v %v", err, b)
	}
	// 探针在线时不能重签，失联后可以重装；在线 agent 不挡探针
	client.Asset.UpdateOne(a).SetAgentID(uuid.New()).SetLastSeen(time.Now()).SetSensorSeen(time.Now()).ExecX(ctx)
	if _, _, err := s.Enroll(ctx, sensorToken, Request{Hostname: "gw01", Kind: KindSensor, CSR: csr(t, "x")}); !errors.Is(err, ErrSensor) {
		t.Fatalf("在线探针应拒绝重签：%v", err)
	}
	client.Asset.UpdateOne(a).SetSensorSeen(time.Now().Add(-time.Hour)).ExecX(ctx)
	if _, _, err := s.Enroll(ctx, sensorToken, Request{Hostname: "gw01", Kind: KindSensor, CSR: csr(t, "x")}); err != nil {
		t.Fatalf("探针失联后应允许重装（在线 agent 不影响）：%v", err)
	}
}
