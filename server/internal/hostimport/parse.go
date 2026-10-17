package hostimport

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

const MaxDocument = 1 << 20
const MaxHosts = 100

// Host 的 JSON 是预览契约，凭据不会序列化；不把原文交给模型，也不在错误中回显原文。
type Host struct {
	Hostname string `json:"hostname"`
	Address  string `json:"address"`
	OS       string `json:"os"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Kind     string `json:"kind"`
	HostKey  string `json:"hostKey"`
	Secret   Secret `json:"-"`
}

var hostnamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}$`)

func Digest(document string) string {
	sum := sha256.Sum256([]byte(document))
	return hex.EncodeToString(sum[:])
}

// Parse 支持 YAML/JSON hosts 列表、Markdown 内同结构的代码块和主机表格。
// 非结构化叙述不猜测凭据与主机的关联，避免把某台主机的密码配给另一台。
func Parse(document string) ([]Host, error) {
	if len(document) == 0 || len(document) > MaxDocument || !utf8.ValidString(document) {
		return nil, errors.New("文档须为非空 UTF-8 文本，最大 1 MiB")
	}
	var records []map[string]string
	trimmed := strings.TrimSpace(document)
	if strings.HasPrefix(trimmed, "hosts:") || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "- ") {
		var err error
		records, err = parseYAML(trimmed)
		if err != nil {
			return nil, err
		}
	} else {
		scanner := bufio.NewScanner(strings.NewReader(document))
		scanner.Buffer(make([]byte, 4096), MaxDocument)
		var block strings.Builder
		inBlock := false
		var headers []string
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "```") {
				if inBlock {
					rows, err := parseYAML(block.String())
					if err != nil {
						return nil, err
					}
					records = append(records, rows...)
					block.Reset()
					inBlock = false
				} else if line == "```yaml" || line == "```yml" || line == "```json" {
					inBlock = true
				}
				headers = nil
				continue
			}
			if inBlock {
				block.WriteString(scanner.Text())
				block.WriteByte('\n')
				continue
			}
			if !strings.HasPrefix(line, "|") {
				headers = nil
				continue
			}
			cells := strings.Split(strings.TrimSuffix(strings.TrimPrefix(line, "|"), "|"), "|")
			if headers == nil {
				candidate := make([]string, len(cells))
				hasHost := false
				for i, cell := range cells {
					candidate[i] = fieldName(cell)
					hasHost = hasHost || candidate[i] == "address"
				}
				if hasHost {
					headers = candidate
				}
				continue
			}
			if strings.Trim(strings.Join(cells, ""), " :-\t") == "" {
				continue
			}
			if len(cells) != len(headers) {
				return nil, errors.New("主机表格列数不一致；含竖线或多行的密码/私钥请用 YAML 代码块")
			}
			row := map[string]string{}
			for i, field := range headers {
				if field != "" {
					row[field] = strings.Trim(strings.TrimSpace(cells[i]), "`")
				}
			}
			records = append(records, row)
		}
		if scanner.Err() != nil || inBlock {
			return nil, errors.New("文档过长或代码块未闭合")
		}
	}
	if len(records) == 0 || len(records) > MaxHosts {
		return nil, errors.New("未找到主机记录，或记录超过 100 条；请使用主机表格或 hosts YAML/JSON")
	}
	out := make([]Host, 0, len(records))
	seen := map[string]bool{}
	for i, row := range records {
		h, err := normalize(row)
		if err != nil {
			return nil, fmt.Errorf("第 %d 条主机：%w", i+1, err)
		}
		if seen[h.Hostname] {
			return nil, fmt.Errorf("第 %d 条主机名重复", i+1)
		}
		seen[h.Hostname] = true
		out = append(out, h)
	}
	return out, nil
}

func parseYAML(text string) ([]map[string]string, error) {
	var node yaml.Node
	decoder := yaml.NewDecoder(strings.NewReader(text))
	if decoder.Decode(&node) != nil || len(node.Content) != 1 {
		return nil, errors.New("主机 YAML/JSON 格式错误")
	}
	var extra yaml.Node
	if decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("只支持单个 YAML/JSON 文档")
	}
	root := node.Content[0]
	if root.Kind == yaml.MappingNode {
		if len(root.Content) != 2 || root.Content[0].Value != "hosts" {
			return nil, errors.New("YAML/JSON 顶层须为 hosts 列表")
		}
		root = root.Content[1]
	}
	if root.Kind != yaml.SequenceNode {
		return nil, errors.New("hosts 必须是列表")
	}
	rows := make([]map[string]string, 0, len(root.Content))
	for _, n := range root.Content {
		if n.Kind != yaml.MappingNode {
			return nil, errors.New("每条主机须为字段映射")
		}
		row := map[string]string{}
		for i := 0; i < len(n.Content); i += 2 {
			key := fieldName(n.Content[i].Value)
			value := n.Content[i+1]
			if key == "" || value.Kind != yaml.ScalarNode {
				return nil, errors.New("主机字段不支持或不是文本；请按导入模板填写")
			}
			if _, ok := row[key]; ok {
				return nil, errors.New("主机字段重复")
			}
			row[key] = value.Value
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func fieldName(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "hostname", "主机名", "名称":
		return "hostname"
	case "address", "ip", "ip地址", "地址", "主机地址":
		return "address"
	case "os", "系统", "操作系统":
		return "os"
	case "port", "ssh_port", "端口", "ssh端口":
		return "port"
	case "username", "user", "用户名", "账号", "ssh用户":
		return "username"
	case "password", "密码", "口令":
		return "password"
	case "private_key", "privatekey", "私钥":
		return "private_key"
	case "passphrase", "私钥口令":
		return "passphrase"
	case "host_key", "hostkey", "主机指纹":
		return "host_key"
	}
	return ""
}

func normalize(row map[string]string) (Host, error) {
	h := Host{Hostname: strings.TrimSpace(row["hostname"]), Address: strings.TrimSpace(row["address"]), OS: strings.ToLower(strings.TrimSpace(row["os"])), Port: 22, Username: strings.TrimSpace(row["username"]), HostKey: strings.TrimSpace(row["host_key"]), Secret: Secret{Password: row["password"], PrivateKey: row["private_key"], Passphrase: row["passphrase"]}}
	if h.Hostname == "" {
		h.Hostname = h.Address
	}
	if !hostnamePattern.MatchString(h.Hostname) {
		return h, errors.New("主机名不合法")
	}
	if net.ParseIP(h.Address) == nil && !hostnamePattern.MatchString(h.Address) {
		return h, errors.New("地址须为 IP 或主机名，不能带 URL、路径或命令")
	}
	if h.OS == "" {
		h.OS = "linux"
	}
	if h.OS != "linux" && h.OS != "windows" {
		return h, errors.New("os 只支持 linux 或 windows")
	}
	if row["port"] != "" {
		port, err := strconv.Atoi(row["port"])
		if err != nil || port < 1 || port > 65535 {
			return h, errors.New("端口不合法")
		}
		h.Port = port
	}
	if h.Secret.Password != "" && h.Secret.PrivateKey != "" {
		return h, errors.New("密码与私钥只能选一种")
	}
	switch {
	case h.Secret.Password != "":
		h.Kind = "password"
	case h.Secret.PrivateKey != "":
		h.Kind = "private_key"
		var err error
		if h.Secret.Passphrase != "" {
			_, err = ssh.ParsePrivateKeyWithPassphrase([]byte(h.Secret.PrivateKey), []byte(h.Secret.Passphrase))
		} else {
			_, err = ssh.ParsePrivateKey([]byte(h.Secret.PrivateKey))
		}
		if err != nil {
			return h, errors.New("私钥无效或私钥口令不正确")
		}
	default:
		h.Kind = "none"
	}
	if h.Kind != "none" && (h.Username == "" || strings.ContainsAny(h.Username, "\r\n\x00")) {
		return h, errors.New("凭据缺少有效用户名")
	}
	if h.Secret.Passphrase != "" && h.Kind != "private_key" {
		return h, errors.New("私钥口令必须配合私钥")
	}
	if h.HostKey != "" && !ValidFingerprint(h.HostKey) {
		return h, errors.New("主机指纹须为 SHA256 格式")
	}
	return h, nil
}
