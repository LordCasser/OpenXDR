// suricata-import 顺序导入 EVE 文件中的 alert；无效行跳过并报告行号，请求失败即停止，重跑由服务端幂等去重。
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"openxdr/server/internal/suricata"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "用法：SURICATA_URL=https://平台/api/integration/v1/suricata/events SURICATA_TOKEN=集成令牌 suricata-import eve.json（- 表示标准输入）")
		os.Exit(1)
	}
	var input io.Reader = os.Stdin
	if os.Args[1] != "-" {
		file, err := os.Open(os.Args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "无法读取 EVE 文件")
			os.Exit(1)
		}
		defer file.Close()
		input = file
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	n, skipped, err := run(context.Background(), input, client, os.Getenv("SURICATA_URL"), os.Getenv("SURICATA_TOKEN"))
	if len(skipped) > 0 {
		fmt.Fprintf(os.Stderr, "跳过 %d 行无效告警（重跑不会改变结果），行号：%v\n", len(skipped), skipped[:min(len(skipped), 20)])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "已确认 %d 条告警；%v。保留文件，修复后可从头重跑。\n", n, err)
		os.Exit(1)
	}
	fmt.Printf("已确认 %d 条告警（重复事件由服务端去重）\n", n)
	if len(skipped) > 0 {
		os.Exit(2)
	}
}

// run 返回已确认条数与被跳过的行号。无效行与服务端 400 只跳过，重试也不会成功；
// 网络错误和其他状态码可能是暂时故障，立即停止。
func run(ctx context.Context, input io.Reader, client *http.Client, endpoint, token string) (count int, skipped []int, err error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return 0, nil, fmt.Errorf("SURICATA_URL 无效")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1")) {
		return 0, nil, fmt.Errorf("远程接入必须使用 HTTPS")
	}
	if len(token) < 32 {
		return 0, nil, fmt.Errorf("SURICATA_TOKEN 未配置或不足 32 字符")
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), suricata.MaxEventBytes+1)
	line := 0
	for scanner.Scan() {
		line++
		raw := scanner.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		var header struct {
			Type string `json:"event_type"`
		}
		if json.Unmarshal(raw, &header) != nil || header.Type == "" {
			skipped = append(skipped, line)
			continue
		}
		if header.Type != "alert" {
			continue
		}
		event, err := suricata.Parse(raw)
		if err != nil {
			skipped = append(skipped, line)
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(event.Raw))
		if err != nil {
			return count, skipped, fmt.Errorf("接入 URL 无效")
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return count, skipped, fmt.Errorf("第 %d 行请求失败，是否已接收未知", line)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode == http.StatusBadRequest {
			skipped = append(skipped, line)
			continue
		}
		if resp.StatusCode != http.StatusAccepted {
			return count, skipped, fmt.Errorf("第 %d 行接入返回 HTTP %d", line, resp.StatusCode)
		}
		count++
	}
	if scanner.Err() != nil {
		return count, skipped, fmt.Errorf("第 %d 行后读取失败或单行超过 256 KiB", line)
	}
	return count, skipped, nil
}
