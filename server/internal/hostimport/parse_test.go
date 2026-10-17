package hostimport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/google/uuid"
	"openxdr/server/ent"
)

func TestParseDocumentsWithoutExposingSecrets(t *testing.T) {
	docs := []string{
		"# 资产\n\n| 主机名 | IP | 账号 | 密码 | 系统 |\n|---|---|---|---|---|\n| app-01 | 192.0.2.10 | root | test-secret | linux |\n",
		"hosts:\n  - hostname: app-01\n    address: 192.0.2.10\n    username: root\n    password: test-secret\n",
		"说明\n```json\n{\"hosts\":[{\"hostname\":\"app-01\",\"address\":\"192.0.2.10\",\"username\":\"root\",\"password\":\"test-secret\"}]}\n```\n",
	}
	for _, doc := range docs {
		hosts, err := Parse(doc)
		if err != nil {
			t.Fatal(err)
		}
		if len(hosts) != 1 || hosts[0].Secret.Password != "test-secret" || hosts[0].Kind != "password" {
			t.Fatal("凭据未关联到主机")
		}
		raw, err := json.Marshal(hosts)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "test-secret") || strings.Contains(string(raw), "Secret") {
			t.Fatal("预览泄露了密码")
		}
	}
}

func TestParserRejectsAmbiguousOrInvalidInput(t *testing.T) {
	for _, doc := range []string{
		"hosts:\n - address: 192.0.2.1\n   password: secret-error-marker\n",
		"hosts:\n - address: 192.0.2.1\n   private_key: secret-error-marker\n   username: root\n",
		"hosts:\n - address: 192.0.2.1\n   command: secret-error-marker\n",
		"hosts:\n - address: 192.0.2.1\n - address: 192.0.2.1\n",
		"hosts:\n - address: 'https://example.com'\n",
		"hosts:\n - address: 192.0.2.1\n   address: 192.0.2.2\n",
		"hosts:\n - address: 192.0.2.1\n---\nhosts: []",
		"hosts:\n - address: 192.0.2.1\n   port: 0\n",
		"hosts:\n - address: 192.0.2.1\n   host_key: SHA256:bad\n",
	} {
		_, err := Parse(doc)
		if err == nil {
			t.Fatal("未拒绝无效文档")
		}
		if strings.Contains(err.Error(), "secret-error-marker") {
			t.Fatal("错误回显了凭据")
		}
	}
}

func TestVaultBindsIdentityAndConnectionMetadata(t *testing.T) {
	v, err := NewVault(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	c := &ent.HostCredential{ID: uuid.New(), AssetID: uuid.New(), GroupID: uuid.New(), Address: "192.0.2.1", Port: 22, Username: "root", Kind: "password"}
	secret := Secret{Password: "secret-marker"}
	a, err := v.Seal(secret, binding(c))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := v.Seal(secret, binding(c))
	if string(a) == string(b) || strings.Contains(string(a), secret.Password) {
		t.Fatal("密文没有独立 nonce 或出现明文")
	}
	got, err := v.Open(a, binding(c))
	if err != nil || got != secret {
		t.Fatal("不能解密原凭据")
	}
	for _, mutate := range []func(*ent.HostCredential){
		func(c *ent.HostCredential) { c.GroupID = uuid.New() }, func(c *ent.HostCredential) { c.AssetID = uuid.New() },
		func(c *ent.HostCredential) { c.Address = "192.0.2.2" }, func(c *ent.HostCredential) { c.Username = "another" },
		func(c *ent.HostCredential) { c.HostKey = "changed" },
	} {
		other := *c
		mutate(&other)
		if _, err := v.Open(a, binding(&other)); err == nil {
			t.Fatal("调换身份或地址仍可解密")
		}
	}
	a[len(a)-1] ^= 1
	if _, err := v.Open(a, binding(c)); err == nil {
		t.Fatal("篡改密文仍可解密")
	}
	if _, err := NewVault("invalid"); err == nil {
		t.Fatal("接受了无效密钥")
	}
}

func TestParsePrivateKeyFromMarkdownYAML(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	private := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	document := "配置\n```yaml\nhosts:\n - hostname: win-01\n   address: 192.0.2.20\n   os: windows\n   username: Administrator\n   private_key: |\n     " + strings.ReplaceAll(strings.TrimSpace(private), "\n", "\n     ") + "\n```\n"
	hosts, err := Parse(document)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].Kind != "private_key" || hosts[0].Secret.PrivateKey != private || hosts[0].OS != "windows" {
		t.Fatal("未正确识别 Windows 主机及多行私钥")
	}
	preview, _ := json.Marshal(hosts)
	if strings.Contains(string(preview), "PRIVATE KEY") || strings.Contains(string(preview), base64.StdEncoding.EncodeToString(der)) {
		t.Fatal("预览泄露私钥")
	}
}
