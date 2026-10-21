package suricata

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"time"
)

const MaxEventBytes = 256 << 10

// Accept 读取一条 EVE 告警，以服务端认定的来源交给 publish。
// 只有队列确认持久接收才返回 202；失败可原样重传。错误格式由调用方的 fail 决定。
func Accept(w http.ResponseWriter, r *http.Request, origin Origin, publish func(context.Context, Origin, Event) error, fail func(status int, message string)) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxEventBytes))
	if err != nil {
		fail(http.StatusRequestEntityTooLarge, "报文读取失败或超过 256 KiB")
		return
	}
	event, err := Parse(raw)
	if err != nil {
		fail(http.StatusBadRequest, err.Error())
		return
	}
	origin.Received = time.Now().UTC()
	if err := publish(r.Context(), origin, event); err != nil {
		slog.Error("Suricata 告警接入失败", "observer", origin.Observer, "err", err)
		fail(http.StatusServiceUnavailable, "暂时无法接收，请保留原始事件重试")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
