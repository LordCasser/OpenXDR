package hostimport

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/ssh"
	"openxdr/server/ent"
)

func ValidFingerprint(value string) bool {
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "SHA256:"))
	return strings.HasPrefix(value, "SHA256:") && err == nil && len(raw) == 32
}

// EnrollmentURL 只接受控制台 HTTPS origin，不让部署配置变成远程脚本参数注入。
func EnrollmentURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || strings.ContainsAny(raw, "\r\n'\" ") {
		return "", errors.New("ENROLL_PUBLIC_URL 须为可信 HTTPS 控制台地址，不含路径、账号或查询参数")
	}
	return strings.TrimRight(raw, "/"), nil
}

// Install 只执行平台安装脚本，不执行文档中的命令。指纹必须由操作者独立核对，不能自动信任扫描结果。
// 该方法返回只说明安装脚本完成；主机实际在线状态由后续 mTLS 注册和心跳确定。
func Install(ctx context.Context, c *ent.HostCredential, secret Secret, hostname, osName, publicURL, token, script, fingerprint string) error {
	publicURL, err := EnrollmentURL(publicURL)
	if err != nil {
		return err
	}
	if !ValidFingerprint(fingerprint) {
		return errors.New("请先提供独立核对过的 SSH SHA256 主机指纹")
	}
	if c.HostKey != "" && c.HostKey != fingerprint {
		return errors.New("指纹与已保存凭据不一致")
	}
	var method ssh.AuthMethod
	if c.Kind == "password" {
		method = ssh.Password(secret.Password)
	} else {
		var signer ssh.Signer
		if secret.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(secret.PrivateKey), []byte(secret.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(secret.PrivateKey))
		}
		if err != nil {
			return errors.New("私钥不可用")
		}
		method = ssh.PublicKeys(signer)
	}
	addr := net.JoinHostPort(c.Address, strconv.Itoa(c.Port))
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return errors.New("无法连接 SSH 地址")
	}
	defer conn.Close()
	deadline := time.Now().Add(2 * time.Minute)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	config := &ssh.ClientConfig{User: c.Username, Auth: []ssh.AuthMethod{method}, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if subtle.ConstantTimeCompare([]byte(ssh.FingerprintSHA256(key)), []byte(fingerprint)) != 1 {
			return errors.New("SSH 主机指纹不匹配")
		}
		return nil
	}}
	cc, ch, req, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return errors.New("SSH 身份验证或主机指纹校验失败")
	}
	client := ssh.NewClient(cc, ch, req)
	defer client.Close()
	// 防止文档地址和主机名错配，导致实际安装到另一个资产。
	session, err := client.NewSession()
	if err != nil {
		return errors.New("无法建立 SSH 会话")
	}
	var name limitedName
	session.Stdout = &name
	session.Stderr = io.Discard
	err = session.Run("hostname")
	session.Close()
	if err != nil || strings.TrimSpace(name.value) != hostname {
		return errors.New("目标主机名与导入记录不一致，未执行安装")
	}
	session, err = client.NewSession()
	if err != nil {
		return errors.New("无法建立 SSH 安装会话")
	}
	defer session.Close()
	session.Stdout = io.Discard
	session.Stderr = io.Discard
	command := "sh -s"
	if c.Username != "root" {
		command = "sudo -n " + command
	}
	if osName == "windows" {
		// 编码短入口兼容 Windows 默认 shell；脚本和短期令牌走 stdin，避免命令行长度限制和令牌暴露。
		text := "$ErrorActionPreference='Stop'; try { & ([scriptblock]::Create([Console]::In.ReadToEnd())) } catch { exit 1 }"
		session.Stdin = strings.NewReader("& {\n" + script + "\n} '" + publicURL + "' '" + token + "'")
		units := utf16.Encode([]rune(text))
		data := make([]byte, len(units)*2)
		for i, v := range units {
			binary.LittleEndian.PutUint16(data[i*2:], v)
		}
		command = "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + base64.StdEncoding.EncodeToString(data)
	} else {
		session.Stdin = strings.NewReader("set -- '" + publicURL + "' '" + token + "'\n" + script)
	}
	if err = session.Run(command); err != nil {
		return errors.New("安装未确认完成；先核对目标服务与平台心跳，勿直接重试")
	}
	return nil
}

type limitedName struct{ value string }

func (b *limitedName) Write(p []byte) (int, error) {
	n := len(p)
	if len(b.value)+n > 254 {
		return 0, errors.New("主机名输出过长")
	}
	b.value += string(p)
	return n, nil
}
