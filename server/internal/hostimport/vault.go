// Package hostimport 从运维文档提取主机及凭据；明文只在请求和实际连接时短暂存在。
package hostimport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
)

type Secret struct {
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"privateKey,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

type Vault struct{ aead cipher.AEAD }

// NewVault 密钥由独立环境变量提供，各 HA 节点使用同一把，禁止回退到登录密码或数据库内的密钥。
func NewVault(key string) (*Vault, error) {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("HOST_CREDENTIAL_KEY 必须是 base64 编码的 32 字节密钥")
	}
	defer clear(raw)
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: aead}, nil
}

func (v *Vault) Seal(secret Secret, binding string) ([]byte, error) {
	if v == nil {
		return nil, errors.New("未配置 HOST_CREDENTIAL_KEY，不能保存凭据")
	}
	plain, err := json.Marshal(secret)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	return v.sealBytes(plain, binding)
}

func (v *Vault) sealBytes(plain []byte, binding string) ([]byte, error) {
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return v.aead.Seal(nonce, nonce, plain, []byte(binding)), nil
}

func (v *Vault) Open(sealed []byte, binding string) (Secret, error) {
	var out Secret
	plain, err := v.openBytes(sealed, binding)
	if err != nil {
		return out, err
	}
	defer clear(plain)
	if err = json.Unmarshal(plain, &out); err != nil {
		return Secret{}, errors.New("凭据不可解密")
	}
	return out, nil
}

func (v *Vault) openBytes(sealed []byte, binding string) ([]byte, error) {
	if v == nil || len(sealed) < v.aead.NonceSize() {
		return nil, errors.New("凭据不可解密")
	}
	n := v.aead.NonceSize()
	plain, err := v.aead.Open(nil, sealed[:n], sealed[n:], []byte(binding))
	if err != nil {
		return nil, errors.New("凭据不可解密")
	}
	return plain, nil
}
