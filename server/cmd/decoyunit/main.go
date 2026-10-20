// decoyunit 将非秘密布放参数转换为待审查的 systemd unit。
package main

import (
	"flag"
	"fmt"
	"os"

	"openxdr/server/internal/decoy"
)

func main() {
	platform := flag.String("platform", "", "平台 HTTPS origin")
	deployment := flag.String("deployment", "", "控制台登记 UUID")
	kind := flag.String("kind", "", "ssh、http 或 file")
	listen := flag.String("listen-host", "127.0.0.1", "显式监听 IP，默认仅回环")
	fileRoot := flag.String("file-root", "", "文件载体的父目录：已存在、仅 root 可写、业务用户会浏览")
	flag.Parse()
	unit, err := decoy.ServiceUnit(*platform, *deployment, *kind, *listen, *fileRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err = os.Stdout.WriteString(unit); err != nil {
		os.Exit(1)
	}
}
