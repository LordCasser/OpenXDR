// Package sid 校验 Windows SID 的文本与二进制表示。
package sid

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

func Canonical(value string) (string, error) {
	parts := strings.Split(value, "-")
	if len(parts) < 4 || len(parts) > 18 || parts[0] != "S" || parts[1] != "1" {
		return "", fmt.Errorf("SID 格式无效")
	}
	for i := 2; i < len(parts); i++ {
		for _, c := range parts[i] {
			if c < '0' || c > '9' {
				return "", fmt.Errorf("SID 数值无效")
			}
		}
		bits := 32
		if i == 2 {
			bits = 48
		}
		n, err := strconv.ParseUint(parts[i], 10, bits)
		if err != nil {
			return "", fmt.Errorf("SID 数值无效")
		}
		parts[i] = strconv.FormatUint(n, 10)
	}
	sid := strings.Join(parts, "-")
	if sid == "S-1-0-0" {
		return "", nil
	}
	return sid, nil
}

// FromBinary 解码目录 objectSid；拒绝长度不符、尾随数据或不支持的修订号。
func FromBinary(raw []byte) (string, error) {
	if len(raw) < 8 || raw[0] != 1 || raw[1] < 1 || raw[1] > 15 || len(raw) != 8+4*int(raw[1]) {
		return "", fmt.Errorf("SID 二进制格式无效")
	}
	var authority uint64
	for _, b := range raw[2:8] {
		authority = authority<<8 | uint64(b)
	}
	parts := []string{"S", "1", strconv.FormatUint(authority, 10)}
	for i := 0; i < int(raw[1]); i++ {
		parts = append(parts, strconv.FormatUint(uint64(binary.LittleEndian.Uint32(raw[8+4*i:12+4*i])), 10))
	}
	return Canonical(strings.Join(parts, "-"))
}
