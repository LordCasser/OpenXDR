//go:build integration

package enroll

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/testdb"
)

func testCA(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600)
	return certFile, keyFile
}

func csr(t *testing.T, cn string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestEnrollIssuesBoundCertAndGuardsIdentity(t *testing.T) {
	ctx, client := testdb.New(t)
	caFile, keyFile := testCA(t)
	t.Setenv("TLS_CA_FILE", caFile)
	t.Setenv("TLS_CA_KEY_FILE", keyFile)
	t.Setenv("ENROLL_GRPC_URL", "https://xdr:8081")
	s, err := FromEnv(client, 10*time.Minute)
	if err != nil || s.Disabled() != "" {
		t.Fatalf("应可接入：%v %q", err, s.Disabled())
	}

	web := client.Group.Create().SetName("web").SaveX(ctx)
	db := client.Group.Create().SetName("db").SaveX(ctx)
	token, _, err := s.Issue(ctx, web.ID, "admin", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// CSR 里的 CN 不采信，证书按请求的主机名签
	a, grant, err := s.Enroll(ctx, token, Request{Hostname: "web01", OS: "linux", CSR: csr(t, "host:pve1")})
	if err != nil {
		t.Fatal(err)
	}
	if *a.GroupID != web.ID || grant.Server != "https://xdr:8081" {
		t.Fatalf("应接入 web 组并下发地址：%+v %+v", a, grant)
	}
	block, _ := pem.Decode([]byte(grant.Cert))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(grant.CA))
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("证书应能被 CA 验证为客户端证书：%v", err)
	}
	if cert.Subject.CommonName != "host:web01" {
		t.Errorf("CN 应为 host:web01，实际 %q", cert.Subject.CommonName)
	}

	// 已有在线 agent 的主机名不能重签
	client.Asset.UpdateOne(a).SetAgentID(uuid.New()).SetLastSeen(time.Now()).ExecX(ctx)
	if _, _, err := s.Enroll(ctx, token, Request{Hostname: "web01", CSR: csr(t, "x")}); !errors.Is(err, ErrOnline) {
		t.Errorf("在线主机应拒绝重签：%v", err)
	}
	// 失联后可以重装
	client.Asset.UpdateOne(a).SetLastSeen(time.Now().Add(-time.Hour)).ExecX(ctx)
	if _, _, err := s.Enroll(ctx, token, Request{Hostname: "web01", CSR: csr(t, "x")}); err != nil {
		t.Errorf("失联主机应允许重装：%v", err)
	}
	// 令牌不能把别组的主机挪过来
	client.Asset.Create().SetHostname("db01").SetGroupID(db.ID).SaveX(ctx)
	if _, _, err := s.Enroll(ctx, token, Request{Hostname: "db01", CSR: csr(t, "x")}); !errors.Is(err, ErrMoved) {
		t.Errorf("不应改组：%v", err)
	}
	for _, bad := range []string{"", "a b", "../x", "-x"} {
		if _, _, err := s.Enroll(ctx, token, Request{Hostname: bad, CSR: csr(t, "x")}); !errors.Is(err, ErrHostname) {
			t.Errorf("主机名 %q 应拒绝：%v", bad, err)
		}
	}
	if _, _, err := s.Enroll(ctx, token, Request{Hostname: "web02", CSR: "garbage"}); err == nil {
		t.Error("非法 CSR 应拒绝")
	}
	if _, _, err := s.Enroll(ctx, "oxe_wrong", Request{Hostname: "web03", CSR: csr(t, "x")}); !errors.Is(err, ErrToken) {
		t.Errorf("错误令牌应拒绝：%v", err)
	}

	expired, row, _ := s.Issue(ctx, web.ID, "admin", time.Hour)
	client.EnrollToken.UpdateOne(row).SetExpiresAt(time.Now().Add(-time.Minute)).ExecX(ctx)
	if _, _, err := s.Enroll(ctx, expired, Request{Hostname: "web04", CSR: csr(t, "x")}); !errors.Is(err, ErrToken) {
		t.Errorf("过期令牌应拒绝：%v", err)
	}
	revoked, row, _ := s.Issue(ctx, web.ID, "admin", time.Hour)
	client.EnrollToken.UpdateOne(row).SetRevoked(true).ExecX(ctx)
	if _, _, err := s.Enroll(ctx, revoked, Request{Hostname: "web05", CSR: csr(t, "x")}); !errors.Is(err, ErrToken) {
		t.Errorf("撤销令牌应拒绝：%v", err)
	}
	if _, _, err := s.Issue(ctx, web.ID, "admin", 31*24*time.Hour); err == nil {
		t.Error("超过 30 天的有效期应拒绝")
	}
}

// 明文部署只下发地址；mTLS 开了却缺签发密钥时不启用。
func TestEnrollModes(t *testing.T) {
	ctx, client := testdb.New(t)
	t.Setenv("ENROLL_GRPC_URL", "http://xdr:8081")
	s, _ := FromEnv(client, time.Minute)
	g := client.Group.Create().SetName("g").SaveX(ctx)
	token, _, _ := s.Issue(ctx, g.ID, "admin", time.Hour)
	_, grant, err := s.Enroll(ctx, token, Request{Hostname: "h1"})
	if err != nil || grant.Cert != "" || grant.Server != "http://xdr:8081" {
		t.Fatalf("明文部署应只下发地址：%+v %v", grant, err)
	}

	caFile, _ := testCA(t)
	t.Setenv("TLS_CA_FILE", caFile)
	s, _ = FromEnv(client, time.Minute)
	if s.Disabled() == "" {
		t.Fatal("缺 TLS_CA_KEY_FILE 时不应启用")
	}
	if _, _, err := s.Enroll(ctx, token, Request{Hostname: "h2"}); err == nil {
		t.Fatal("未启用时应拒绝接入")
	}

	_, otherKey := testCA(t)
	t.Setenv("TLS_CA_KEY_FILE", otherKey)
	if _, err := FromEnv(client, time.Minute); err == nil {
		t.Fatal("私钥与证书不匹配应报错")
	}
}
