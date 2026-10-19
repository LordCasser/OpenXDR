package directory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

func ldapFixture(t *testing.T, profile string) *LDAP {
	t.Helper()
	l, err := NewLDAP(uuid.New(), uuid.New(), LDAPConfig{URL: "ldaps://directory.example.invalid", BaseDN: "dc=example,dc=invalid", Profile: profile}, nil, func(context.Context) (LDAPCredentials, error) {
		return LDAPCredentials{Username: "reader", Password: "secret"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

type searchFunc func(*ldap.SearchRequest) (*ldap.SearchResult, error)

func (f searchFunc) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) { return f(req) }

func ldapPage(cookie string, entries ...*ldap.Entry) *ldap.SearchResult {
	c := ldap.NewControlPaging(100)
	c.SetCookie([]byte(cookie))
	return &ldap.SearchResult{Entries: entries, Controls: []ldap.Control{c}}
}

func ldapUser(id, name string) *ldap.Entry {
	return ldap.NewEntry("uid="+name+",dc=example,dc=invalid", map[string][]string{"entryUUID": {id}, "uid": {name}})
}

func TestLDAPStableIdentityAndState(t *testing.T) {
	ad := ldapFixture(t, "ad")
	raw, _ := hex.DecodeString("33221100554477668899aabbccddeeff")
	for _, flag := range []string{"512", "514", ""} {
		attrs := map[string][]string{"objectGUID": {string(raw)}, "sAMAccountName": {"name"}}
		if flag != "" {
			attrs["userAccountControl"] = []string{flag}
		}
		a, err := ad.account(ldap.NewEntry("cn=old,dc=example,dc=invalid", attrs))
		if err != nil || a.ExternalID != "00112233-4455-6677-8899-aabbccddeeff" {
			t.Fatalf("GUID 字节序错误: %+v %v", a, err)
		}
		if flag == "" && a.Enabled != nil || flag != "" && (a.Enabled == nil || *a.Enabled != (flag == "512")) {
			t.Fatal("AD 状态错误")
		}
		attrs["sAMAccountName"] = []string{"renamed"}
		b, err := ad.account(ldap.NewEntry("cn=new,dc=example,dc=invalid", attrs))
		if err != nil || b.ExternalID != a.ExternalID {
			t.Fatal("重命名改变身份")
		}
	}
	l := ldapFixture(t, "ldap")
	id := uuid.New().String()
	a, err := l.account(ldapUser(id, "u"))
	if err != nil || a.ExternalID != id || a.Enabled != nil {
		t.Fatal("LDAP 账号契约错误")
	}
	for _, entry := range []*ldap.Entry{nil, ldapUser("", "u"), ldapUser(id, ""), ldap.NewEntry("cn=x", map[string][]string{"uid": {"x", "y"}, "entryUUID": {id}})} {
		if _, err := l.account(entry); err == nil {
			t.Fatal("接受缺失或多值属性")
		}
	}
}

func TestADSIDObservation(t *testing.T) {
	l := ldapFixture(t, "ad")
	guid, _ := hex.DecodeString("33221100554477668899aabbccddeeff")
	sidBytes, _ := hex.DecodeString("010500000000000515000000010000000200000003000000e9030000")
	attrs := map[string][]string{"objectGUID": {string(guid)}, "sAMAccountName": {"account"}, "objectSid": {string(sidBytes)}}
	account, err := l.account(ldap.NewEntry("cn=account", attrs))
	if err != nil || account.WindowsSID != "S-1-5-21-1-2-3-1001" || account.Enabled != nil {
		t.Fatalf("SID 提取失败: %+v %v", account, err)
	}
	scan := Scan{Source: l.source, StartedAt: time.Now(), FinishedAt: time.Now(), Accounts: []Account{account}}
	if err := scan.validate(); err != nil {
		t.Fatal(err)
	}
	other := account
	other.ExternalID = "other"
	scan.Accounts = append(scan.Accounts, other)
	if err := scan.validate(); err == nil {
		t.Fatal("同目录重复 SID 获准")
	}
	scan.Accounts = []Account{account}
	scan.Source.Kind = "ldap"
	if err := scan.validate(); err == nil {
		t.Fatal("非 AD 来源 SID 获准")
	}
	attrs["objectSid"] = []string{"bad"}
	if _, err := l.account(ldap.NewEntry("cn=account", attrs)); err == nil {
		t.Fatal("坏 SID 获准")
	}
	delete(attrs, "objectSid")
	if account, err := l.account(ldap.NewEntry("cn=account", attrs)); err != nil || account.WindowsSID != "" {
		t.Fatal("缺失 SID 被补造")
	}
}

func TestLDAPPages(t *testing.T) {
	l := ldapFixture(t, "ldap")
	calls := 0
	f := searchFunc(func(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
		calls++
		if r.BaseDN != l.config.BaseDN || r.DerefAliases != ldap.NeverDerefAliases || !r.EnforceSizeLimit {
			t.Error("搜索边界错误")
		}
		c := ldap.FindControl(r.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
		if c.PagingSize != 100 {
			t.Error("分页大小错误")
		}
		switch calls {
		case 1:
			return ldapPage("next", ldapUser(uuid.New().String(), "same")), nil
		case 2:
			if string(c.Cookie) != "next" {
				t.Error("游标丢失")
			}
			return ldapPage("last"), nil
		case 3:
			return ldapPage("", ldapUser(uuid.New().String(), "same")), nil
		default:
			t.Fatal("多余请求")
			return nil, nil
		}
	})
	scan, err := l.readPages(context.Background(), f, time.Now())
	if err != nil || len(scan.Accounts) != 2 || calls != 3 {
		t.Fatalf("分页失败: %v", err)
	}
}

func TestLDAPPartialFailures(t *testing.T) {
	id := uuid.New().String()
	for _, failure := range []*ldap.SearchResult{nil, {}, {Referrals: []string{"ldaps://other"}}, ldapPage("repeat"), ldapPage("", ldapUser(id, "duplicate"))} {
		l := ldapFixture(t, "ldap")
		calls := 0
		f := searchFunc(func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			calls++
			if calls == 1 {
				return ldapPage("repeat", ldapUser(id, "one")), nil
			}
			return failure, nil
		})
		scan, err := l.readPages(context.Background(), f, time.Now())
		if err == nil || len(scan.Accounts) != 0 {
			t.Fatal("不完整结果当作成功")
		}
	}
	l := ldapFixture(t, "ldap")
	if scan, err := l.readPages(context.Background(), searchFunc(func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return ldapPage("", ldapUser(id, "u")), fmt.Errorf("secret")
	}), time.Now()); err == nil || len(scan.Accounts) != 0 || err.Error() == "secret" {
		t.Fatal("LDAP 错误未隔离")
	}
}

func TestLDAPCapacityAndCancellation(t *testing.T) {
	l := ldapFixture(t, "ldap")
	calls := 0
	f := searchFunc(func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		calls++
		entries := make([]*ldap.Entry, 100)
		for i := range entries {
			entries[i] = ldapUser(uuid.New().String(), "u")
		}
		return ldapPage(fmt.Sprint(calls), entries...), nil
	})
	if scan, err := l.readPages(context.Background(), f, time.Now()); err == nil || len(scan.Accounts) != 0 || calls != 101 {
		t.Fatal("容量超限未拒绝")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.readPages(ctx, searchFunc(func(*ldap.SearchRequest) (*ldap.SearchResult, error) { t.Fatal("取消后仍搜索"); return nil, nil }), time.Now()); err == nil {
		t.Fatal("取消未生效")
	}
}

func TestLDAPRefusesInsecureConfig(t *testing.T) {
	credentials := func(context.Context) (LDAPCredentials, error) { return LDAPCredentials{}, nil }
	for _, endpoint := range []string{"http://host", "ldaps://u:p@host", "ldap://host?filter=x", "ldaps://host/path", "ldap://host:99999"} {
		if _, err := NewLDAP(uuid.New(), uuid.New(), LDAPConfig{URL: endpoint, BaseDN: "dc=x", Profile: "ad"}, nil, credentials); err == nil {
			t.Fatal("无效地址获准")
		}
	}
	if _, err := NewLDAP(uuid.New(), uuid.New(), LDAPConfig{URL: "ldaps://host", BaseDN: "dc=x", Profile: "ad"}, &tls.Config{InsecureSkipVerify: true}, credentials); err == nil {
		t.Fatal("允许绕过证书验证")
	}
}

// 对真实 TCP 连接检查失败的 StartTLS 之前没有 Bind，避免匿名/明文降级。
func TestLDAPStartTLSBeforeBind(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		packet, err := ber.ReadPacket(conn)
		if err == nil && (len(packet.Children) < 2 || packet.Children[1].Tag != 23) {
			err = fmt.Errorf("首个请求不是 StartTLS")
		}
		result <- err
	}()
	l := ldapFixture(t, "ldap")
	l.config.URL = "ldap://" + listener.Addr().String()
	l.address = listener.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := l.ReadAccounts(ctx); err == nil {
		t.Fatal("未完成 TLS 仍成功")
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestLDAPSTransport(t *testing.T) {
	certServer := httptest.NewTLSServer(nil)
	cert := certServer.Certificate()
	serverTLS := certServer.TLS.Clone()
	certServer.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan error, 1)
	id := uuid.New().String()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(4 * time.Second))
		for _, tag := range []ber.Tag{0, 3} {
			request, err := ber.ReadPacket(conn)
			if err != nil {
				result <- err
				return
			}
			if len(request.Children) < 2 || request.Children[1].Tag != tag {
				result <- fmt.Errorf("LDAP 操作顺序错误")
				return
			}
			message := func(operation *ber.Packet) *ber.Packet {
				p := ber.NewSequence("LDAP message")
				p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, request.Children[0].Value, "id"))
				p.AppendChild(operation)
				return p
			}
			if tag == 3 {
				entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "entry")
				entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "uid=user,dc=example,dc=invalid", "dn"))
				attrs := ber.NewSequence("attributes")
				for name, value := range map[string]string{"entryUUID": id, "uid": "user"} {
					attribute := ber.NewSequence("attribute")
					attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "name"))
					values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "values")
					values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "value"))
					attribute.AppendChild(values)
					attrs.AppendChild(attribute)
				}
				entry.AppendChild(attrs)
				if _, err := conn.Write(message(entry).Bytes()); err != nil {
					result <- err
					return
				}
			}
			responseTag := ber.Tag(1)
			if tag == 3 {
				responseTag = 5
			}
			op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, responseTag, nil, "result")
			op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "success"))
			op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matched DN"))
			op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnostic"))
			response := message(op)
			if tag == 3 {
				controls := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "controls")
				controls.AppendChild(ldap.NewControlPaging(100).Encode())
				response.AppendChild(controls)
			}
			if _, err := conn.Write(response.Bytes()); err != nil {
				result <- err
				return
			}
		}
		result <- nil
	}()
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	l, err := NewLDAP(uuid.New(), uuid.New(), LDAPConfig{URL: "ldaps://" + listener.Addr().String(), BaseDN: "dc=example,dc=invalid", Profile: "ldap"}, &tls.Config{RootCAs: pool}, func(context.Context) (LDAPCredentials, error) {
		return LDAPCredentials{Username: "reader", Password: "test-password"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	scan, err := l.ReadAccounts(ctx)
	if err != nil || len(scan.Accounts) != 1 || scan.Accounts[0].ExternalID != id {
		t.Fatalf("LDAPS 读取失败: %+v %v", scan, err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
