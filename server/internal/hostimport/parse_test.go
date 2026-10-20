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

func TestMarkdownRejectsDuplicateFields(t *testing.T) {
	for name, doc := range map[string]string{
		"address":  "| 主机名 | 地址 | IP |\n| app-01 | 192.0.2.1 | 192.0.2.2 |\n",
		"password": "| 主机名 | 地址 | 账号 | password | 密码 |\n| app-01 | 192.0.2.1 | root | secret-marker | other-secret |\n",
		"username": "| 主机名 | 地址 | username | 账号 | 密码 |\n| app-01 | 192.0.2.1 | root | admin | secret-marker |\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(doc)
			if err == nil || !strings.Contains(err.Error(), "字段重复") {
				t.Fatalf("重复字段应被拒绝，得到 %v", err)
			}
			if strings.Contains(err.Error(), "secret-marker") || strings.Contains(err.Error(), "other-secret") {
				t.Fatal("错误包含了原文凭据")
			}
		})
	}
}

func TestNullCredentialsAreAbsent(t *testing.T) {
	for _, doc := range []string{
		"hosts:\n - address: 192.0.2.1\n   username: root\n   password: null\n",
		"hosts:\n - address: 192.0.2.1\n   password: null\n   private_key: ~\n   passphrase:\n",
		`{"hosts":[{"address":"192.0.2.1","password":null,"private_key":null,"passphrase":null}]}`,
	} {
		hosts, err := Parse(doc)
		if err != nil {
			t.Fatal(err)
		}
		if len(hosts) != 1 || hosts[0].Kind != "none" || hosts[0].Secret != (Secret{}) {
			t.Fatal("null 不应变成凭据内容")
		}
	}
	// 带引号的 null 是用户明确提供的字面密码，不能被清掉。
	hosts, err := Parse("hosts:\n - address: 192.0.2.1\n   username: root\n   password: 'null'\n")
	if err != nil || len(hosts) != 1 || hosts[0].Secret.Password != "null" || hosts[0].Kind != "password" {
		t.Fatal("带引号的字面密码应原样保存")
	}
}

func TestMarkdownSkipsExampleTablesInOtherFences(t *testing.T) {
	for _, fence := range []string{"```bash", "```", "~~~text"} {
		t.Run(fence, func(t *testing.T) {
			doc := "# 运维记录\n" + fence + "\n| 主机名 | 地址 |\n| example | 192.0.2.99 |\n" + fence[:3] + "\n\n| 主机名 | 地址 |\n| real-host | 192.0.2.1 |\n"
			hosts, err := Parse(doc)
			if err != nil || len(hosts) != 1 || hosts[0].Hostname != "real-host" {
				t.Fatalf("普通代码块中的示例不能作为资产导入，数量 %d，错误 %v", len(hosts), err)
			}
		})
	}
}

func TestMarkdownFenceBoundaries(t *testing.T) {
	for _, fence := range []string{"```yaml", "~~~yaml", "````yaml"} {
		t.Run(fence, func(t *testing.T) {
			marker := strings.TrimSuffix(fence, "yaml")
			doc := "# 主机\n" + fence + "\nhosts:\n - hostname: app-01\n   address: 192.0.2.1\n   username: root\n   password: |\n     ```\n     preserved\n" + marker + "\n"
			hosts, err := Parse(doc)
			if err != nil || len(hosts) != 1 || hosts[0].Secret.Password != "```\npreserved\n" {
				t.Fatalf("不同种类或较短的围栏不应提前结束代码块，错误 %v", err)
			}
		})
	}
	if _, err := Parse("# 主机\n````yaml\nhosts:\n - address: 192.0.2.1\n```\n````\n"); err == nil {
		t.Fatal("较短围栏不能提前结束代码块并忽略尾部内容")
	}
	if _, err := Parse("# 主机\n```yaml\nhosts:\n - address: 192.0.2.1\n``` trailing\n"); err == nil {
		t.Fatal("带尾随内容的标记不能结束代码块")
	}
}

func TestMarkdownInlineCodeIsNotFence(t *testing.T) {
	hosts, err := Parse("# 主机\n```inline``` 只是行内代码\n\n| 主机名 | 地址 |\n| real-host | 192.0.2.1 |\n")
	if err != nil || len(hosts) != 1 || hosts[0].Hostname != "real-host" {
		t.Fatalf("info string 含反引号的行不是围栏，数量 %d，错误 %v", len(hosts), err)
	}
}

func TestNormalizeOSFamilyAndDisplay(t *testing.T) {
	cases := []struct {
		in              string
		family, display string
	}{
		{"", "linux", ""},
		{"  ", "linux", ""},
		{"linux", "linux", ""},
		{"LINUX", "linux", ""},
		{" unix ", "linux", ""},
		{"windows", "windows", ""},
		{"Win", "windows", ""},
		{"Windows Server 2022", "windows", "Windows Server 2022"},
		{"win11", "windows", "win11"},
		{"ubuntu", "linux", "ubuntu"},
		{"Ubuntu 24.04 LTS", "linux", "Ubuntu 24.04 LTS"},
		{"Rocky Linux 9", "linux", "Rocky Linux 9"},
		{"麒麟 V10 SP3", "linux", "麒麟 V10 SP3"},
		{"银河麒麟V10", "linux", "银河麒麟V10"},
		{"统信UOS 20", "linux", "统信UOS 20"},
		{"UOS", "linux", "UOS"},
		{"openEuler 24.03", "linux", "openEuler 24.03"},
	}
	for _, c := range cases {
		family, display, err := normalizeOS(c.in)
		if err != nil || family != c.family || display != c.display {
			t.Fatalf("normalizeOS(%q) = %q, %q, %v；期望 %q, %q", c.in, family, display, err, c.family, c.display)
		}
	}
	for _, bad := range []string{"macos", "Android 14", "freebsd", "路由器"} {
		if _, _, err := normalizeOS(bad); err == nil {
			t.Fatalf("认不出的系统写法应报错：%q", bad)
		}
	}
}

func TestParseKeepsDistroDisplayOnOSColumn(t *testing.T) {
	doc := "# 主机\n\n| 主机名 | 地址 | 系统 | 用户名 | 密码 |\n|---|---|---|---|---|\n| ky-01 | 192.0.2.31 | 麒麟 V10 | root | pw |\n| uos-01 | 192.0.2.32 | 统信UOS 20 | ops | pw |\n| db-01 | 192.0.2.33 | Rocky Linux 9 | root | pw |\n"
	hosts, err := Parse(doc)
	if err != nil || len(hosts) != 3 {
		t.Fatalf("三行主机应全部解析：数量 %d，错误 %v", len(hosts), err)
	}
	want := [][2]string{
		{"linux", "麒麟 V10"},
		{"linux", "统信UOS 20"},
		{"linux", "Rocky Linux 9"},
	}
	for i, h := range hosts {
		if h.OS != want[i][0] || h.OSDisplay != want[i][1] {
			t.Fatalf("第 %d 台系统归一错误：os=%q osDisplay=%q，期望 %v", i+1, h.OS, h.OSDisplay, want[i])
		}
	}
	if _, err := Parse("| 主机名 | 地址 | 系统 |\n|---|---|---|\n| mac-01 | 192.0.2.9 | macOS 14 |\n"); err == nil {
		t.Fatal("认不出的系统写法应整行报错，宁拒不猜")
	}
}
