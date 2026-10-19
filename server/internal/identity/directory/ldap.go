package directory

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"openxdr/server/internal/identity/sid"
)

type LDAPCredentials struct{ Username, Password string }
type LDAPCredentialProvider func(context.Context) (LDAPCredentials, error)

type LDAPConfig struct {
	URL    string
	BaseDN string
	// Profile 为 ad 或 ldap。默认分别读取 objectGUID/sAMAccountName 与 entryUUID/uid。
	Profile string
	Filter  string
}

type LDAP struct {
	source      Source
	config      LDAPConfig
	address     string
	tlsConfig   *tls.Config
	credentials LDAPCredentialProvider
}

func NewLDAP(id, groupID uuid.UUID, config LDAPConfig, tlsConfig *tls.Config, credentials LDAPCredentialProvider) (*LDAP, error) {
	u, err := url.Parse(config.URL)
	if err != nil || (u.Scheme != "ldaps" && u.Scheme != "ldap") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return nil, fmt.Errorf("LDAP 地址无效")
	}
	if !validText(config.BaseDN, 4096) || credentials == nil {
		return nil, fmt.Errorf("LDAP 搜索根或凭据提供器无效")
	}
	if _, err := ldap.ParseDN(config.BaseDN); err != nil {
		return nil, fmt.Errorf("LDAP 搜索根格式无效")
	}
	switch config.Profile {
	case "ad":
		if config.Filter == "" {
			config.Filter = "(&(objectCategory=person)(objectClass=user))"
		}
	case "ldap":
		if config.Filter == "" {
			config.Filter = "(objectClass=inetOrgPerson)"
		}
	default:
		return nil, fmt.Errorf("LDAP 来源类型无效")
	}
	if !validText(config.Filter, 4096) {
		return nil, fmt.Errorf("LDAP 搜索条件无效")
	}
	if _, err := ldap.CompileFilter(config.Filter); err != nil {
		return nil, fmt.Errorf("LDAP 搜索条件格式无效")
	}
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	if tlsConfig != nil {
		c = tlsConfig.Clone()
	}
	if c.InsecureSkipVerify {
		return nil, fmt.Errorf("LDAP 不允许跳过 TLS 证书验证")
	}
	if c.MinVersion < tls.VersionTLS12 {
		c.MinVersion = tls.VersionTLS12
	}
	c.ServerName = u.Hostname()
	port := u.Port()
	if port == "" {
		port = "636"
		if u.Scheme == "ldap" {
			port = "389"
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("LDAP 端口无效")
	}
	source := Source{ID: id, GroupID: groupID, Kind: config.Profile, Authority: strings.TrimRight(u.String(), "/") + "/?base=" + url.QueryEscape(config.BaseDN)}
	if err := source.validate(); err != nil {
		return nil, err
	}
	return &LDAP{source: source, config: config, address: net.JoinHostPort(u.Hostname(), port), tlsConfig: c, credentials: credentials}, nil
}

func (l *LDAP) ReadAccounts(ctx context.Context) (Scan, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	started := time.Now().UTC()
	credentials, err := l.credentials(ctx)
	if err != nil || !validText(credentials.Username, 4096) || credentials.Password == "" || len(credentials.Password) > 65536 {
		return Scan{}, fmt.Errorf("LDAP 绑定凭据缺失或无效")
	}
	conn, err := l.connect(ctx)
	if err != nil {
		return Scan{}, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := conn.Bind(credentials.Username, credentials.Password); err != nil {
		return Scan{}, fmt.Errorf("LDAP 绑定失败")
	}
	return l.readPages(ctx, conn, started)
}

func (l *LDAP) connect(ctx context.Context) (*ldap.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var raw net.Conn
	var err error
	// url.Parse 会把协议名转小写、校验能过，这里也要不分大小写，否则 LDAPS:// 会按明文连 636
	isTLS := strings.HasPrefix(strings.ToLower(l.config.URL), "ldaps:")
	if isTLS {
		raw, err = (&tls.Dialer{NetDialer: dialer, Config: l.tlsConfig}).DialContext(ctx, "tcp", l.address)
	} else {
		raw, err = dialer.DialContext(ctx, "tcp", l.address)
	}
	if err != nil {
		return nil, fmt.Errorf("LDAP 连接失败")
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := raw.SetDeadline(deadline); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("LDAP 连接期限设置失败")
		}
	}
	conn := ldap.NewConn(raw, isTLS)
	conn.Start()
	conn.SetTimeout(30 * time.Second)
	if !isTLS {
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		err = conn.StartTLS(l.tlsConfig)
		stop()
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("LDAP StartTLS 失败")
		}
	}
	return conn, nil
}

type ldapSearcher interface {
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
}

func (l *LDAP) readPages(ctx context.Context, conn ldapSearcher, started time.Time) (Scan, error) {
	result := Scan{Source: l.source, StartedAt: started, Accounts: []Account{}}
	attributes := []string{"entryUUID", "uid"}
	if l.config.Profile == "ad" {
		attributes = []string{"objectGUID", "objectSid", "sAMAccountName", "userAccountControl"}
	}
	seen := map[string]bool{}
	cookies := map[string]bool{}
	var cookie []byte
	for page := 0; page < 1000; page++ {
		if err := ctx.Err(); err != nil {
			return Scan{}, err
		}
		control := ldap.NewControlPaging(100)
		control.SetCookie(cookie)
		request := ldap.NewSearchRequest(l.config.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 10001, 30, false, l.config.Filter, attributes, []ldap.Control{control})
		request.EnforceSizeLimit = true
		response, err := conn.Search(request)
		if ctx.Err() != nil {
			return Scan{}, ctx.Err()
		}
		if err != nil || response == nil {
			return Scan{}, fmt.Errorf("LDAP 搜索失败")
		}
		if len(response.Referrals) > 0 || len(response.Entries) > 100 || len(result.Accounts)+len(response.Entries) > 10000 {
			return Scan{}, fmt.Errorf("LDAP 搜索返回转介或超过上限")
		}
		paging, ok := ldap.FindControl(response.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
		if !ok || len(paging.Cookie) > 16384 {
			return Scan{}, fmt.Errorf("LDAP 分页控制缺失或无效")
		}
		for _, entry := range response.Entries {
			account, err := l.account(entry)
			if err != nil || seen[account.ExternalID] {
				return Scan{}, fmt.Errorf("LDAP 账号属性缺失、无效或重复")
			}
			seen[account.ExternalID] = true
			result.Accounts = append(result.Accounts, account)
		}
		if len(paging.Cookie) == 0 {
			result.FinishedAt = time.Now().UTC()
			return result, nil
		}
		if cookies[string(paging.Cookie)] {
			return Scan{}, fmt.Errorf("LDAP 分页游标重复")
		}
		cookies[string(paging.Cookie)] = true
		cookie = append([]byte(nil), paging.Cookie...)
	}
	return Scan{}, fmt.Errorf("LDAP 搜索超过分页上限")
}

func (l *LDAP) account(entry *ldap.Entry) (Account, error) {
	if entry == nil {
		return Account{}, fmt.Errorf("LDAP 空条目")
	}
	idAttr, nameAttr := "entryUUID", "uid"
	if l.config.Profile == "ad" {
		idAttr, nameAttr = "objectGUID", "sAMAccountName"
	}
	ids := entry.GetEqualFoldRawAttributeValues(idAttr)
	names := entry.GetEqualFoldAttributeValues(nameAttr)
	if len(ids) != 1 || len(names) != 1 || !validText(names[0], 1024) {
		return Account{}, fmt.Errorf("LDAP 标识或名称属性不唯一")
	}
	var id uuid.UUID
	var err error
	if l.config.Profile == "ad" {
		id, err = adGUID(ids[0])
	} else {
		id, err = uuid.Parse(string(ids[0]))
	}
	if err != nil || id == uuid.Nil {
		return Account{}, fmt.Errorf("LDAP 稳定标识无效")
	}
	account := Account{ExternalID: id.String(), Username: names[0]}
	if l.config.Profile != "ad" {
		return account, nil
	}
	sids := entry.GetEqualFoldRawAttributeValues("objectSid")
	if len(sids) > 1 {
		return Account{}, fmt.Errorf("AD SID 属性不唯一")
	}
	if len(sids) == 1 {
		account.WindowsSID, err = sid.FromBinary(sids[0])
		if err != nil || account.WindowsSID == "" {
			return Account{}, fmt.Errorf("AD SID 属性无效")
		}
	}
	flags := entry.GetEqualFoldAttributeValues("userAccountControl")
	if len(flags) == 0 {
		return account, nil
	}
	if len(flags) != 1 {
		return Account{}, fmt.Errorf("AD 状态属性不唯一")
	}
	value, err := strconv.ParseUint(flags[0], 10, 32)
	if err != nil {
		return Account{}, fmt.Errorf("AD 状态属性无效")
	}
	enabled := value&2 == 0
	account.Enabled = &enabled
	return account, nil
}

// AD objectGUID 的前三段使用小端，后八字节保持原顺序。
func adGUID(raw []byte) (uuid.UUID, error) {
	if len(raw) != 16 {
		return uuid.Nil, fmt.Errorf("AD objectGUID 长度无效")
	}
	var id uuid.UUID
	binary.BigEndian.PutUint32(id[0:4], binary.LittleEndian.Uint32(raw[0:4]))
	binary.BigEndian.PutUint16(id[4:6], binary.LittleEndian.Uint16(raw[4:6]))
	binary.BigEndian.PutUint16(id[6:8], binary.LittleEndian.Uint16(raw[6:8]))
	copy(id[8:], raw[8:])
	return id, nil
}
