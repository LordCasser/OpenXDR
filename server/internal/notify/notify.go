// Package notify 告警通知：把研判后的 incident 推到 webhook。
// "一万条进三个出"——那三个出来了得有人知道，不能指望有人一直盯着屏幕。
//
// 投递语义：
//   - AI 启用时等研判完成再推，避免推完 AI 又改口；未启用则事件一出就推
//   - benign 判定静默跳过：AI 说是噪声的不打扰人。但高危及以上照推并标"需复核"——
//     AI 会看错，高危事件被它一句"良性"吞掉的代价太大
//   - 推送目标启用前的历史事件不补发，防止首次启用时轰炸群
//   - 发送失败不落投递标记，下个周期自动重试
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/incident"
	"openxdr/server/internal/review"
)

type Notifier struct {
	DB       *ent.Client
	Settings *Settings
	Interval time.Duration
	// AI 启用时为 true：等 verdict 出来再推
	WaitTriage bool
	Client     *http.Client

	// 推送目标启用的时刻；未配置目标时为零值
	start time.Time
}

func (n *Notifier) Run(ctx context.Context) {
	if n.Client == nil {
		n.Client = &http.Client{Timeout: 10 * time.Second}
	}
	ticker := time.NewTicker(n.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := n.sweep(ctx); err != nil {
				slog.Error("通知批次失败", "err", err)
			}
		}
	}
}

// verdict 只取通知需要的三个字段，其余留给界面
type verdict struct {
	Verdict    string `json:"verdict"`
	Confidence int    `json:"confidence"`
	Summary    string `json:"summary"`
}

func (n *Notifier) sweep(ctx context.Context) error {
	target := n.Settings.Load(ctx)
	if target.URL == "" {
		n.start = time.Time{}
		return nil
	}
	if n.start.IsZero() {
		n.start = time.Now()
	}
	incidents, err := n.DB.Incident.Query().
		Where(incident.NotifiedAtIsNil()).
		Order(ent.Asc(incident.FieldCreatedAt)).
		Limit(20).
		All(ctx)
	if err != nil {
		return err
	}

	for _, inc := range incidents {
		msg, err := n.message(ctx, inc, target.LinkBase)
		if err != nil {
			return err
		}
		send, why := n.decide(inc, msg.Severity)
		if why == "wait" {
			continue // 等研判，先不落标记
		}
		if !send || msg.Severity < target.MinSeverity {
			if err := n.markNotified(ctx, inc); err != nil {
				return err
			}
			continue
		}
		if err := n.post(ctx, target, msg); err != nil {
			slog.Error("webhook 推送失败，下周期重试", "incident", inc.ID, "err", err)
			continue
		}
		if err := n.markNotified(ctx, inc); err != nil {
			return err
		}
		slog.Info("incident 已推送", "id", inc.ID)
	}
	return nil
}

// decide 是否推送。返回 (false, "wait") 表示暂缓，(false, 其他) 表示静默跳过。
func (n *Notifier) decide(inc *ent.Incident, severity int16) (bool, string) {
	if inc.CreatedAt.Before(n.start) {
		return false, "历史事件不补发"
	}
	// 分析师已经处理过的不用再喊人
	if inc.Status == "closed" || inc.Status == "false_positive" {
		return false, "已人工处理"
	}
	if len(inc.AiVerdict) == 0 {
		if n.WaitTriage {
			return false, "wait"
		}
		return true, "" // AI 未启用，事件即推
	}
	var v verdict
	_ = json.Unmarshal(inc.AiVerdict, &v)
	if v.Verdict == "benign" && severity < review.Severity {
		return false, "AI 判定良性"
	}
	return true, ""
}

func (n *Notifier) markNotified(ctx context.Context, inc *ent.Incident) error {
	return n.DB.Incident.UpdateOneID(inc.ID).SetNotifiedAt(time.Now()).Exec(ctx)
}

// Message 通知内容，也是 generic 格式的推送体。
type Message struct {
	IncidentID string    `json:"incidentId"`
	CreatedAt  time.Time `json:"createdAt"`
	Title      string    `json:"title"`
	Verdict    string    `json:"verdict,omitempty"`
	Confidence int       `json:"confidence,omitempty"`
	Summary    string    `json:"summary,omitempty"`
	AlertCount int       `json:"alertCount"`
	Severity   int16     `json:"maxSeverity"`
	Link       string    `json:"link,omitempty"`
}

func (n *Notifier) message(ctx context.Context, inc *ent.Incident, linkBase string) (Message, error) {
	alerts, err := n.DB.Alert.Query().
		Where(alert.IncidentIDEQ(inc.ID)).
		All(ctx)
	if err != nil {
		return Message{}, err
	}
	m := Message{IncidentID: inc.ID.String(), CreatedAt: inc.CreatedAt, AlertCount: len(alerts)}
	for _, a := range alerts {
		if a.Severity > m.Severity {
			m.Severity = a.Severity
		}
	}
	if inc.Title != nil {
		m.Title = *inc.Title
	}
	if len(inc.AiVerdict) > 0 {
		var v verdict
		_ = json.Unmarshal(inc.AiVerdict, &v)
		m.Verdict, m.Confidence, m.Summary = v.Verdict, v.Confidence, v.Summary
	}
	if linkBase != "" {
		m.Link = linkBase + "/?incident=" + m.IncidentID
	}
	return m, nil
}

var severityText = []string{"-", "信息", "低危", "中危", "高危", "严重"}

var verdictText = map[string]string{"malicious": "恶意", "suspicious": "可疑", "benign": "良性，但级别高需人工复核"}

// text 各家 IM 共用的正文。
func text(m Message) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "【OpenXDR】%s\n", m.Title)
	if m.Verdict != "" {
		label := verdictText[m.Verdict]
		if label == "" {
			label = m.Verdict
		}
		fmt.Fprintf(&b, "AI 判定: %s（置信度 %d）\n", label, m.Confidence)
	}
	sev := fmt.Sprint(m.Severity)
	if int(m.Severity) < len(severityText) && m.Severity > 0 {
		sev = severityText[m.Severity]
	}
	fmt.Fprintf(&b, "告警 %d 条，最高级别: %s\n", m.AlertCount, sev)
	if m.Summary != "" {
		fmt.Fprintf(&b, "%s\n", m.Summary)
	}
	if m.Link != "" {
		fmt.Fprintf(&b, "%s\n", m.Link)
	}
	return b.String()
}

// payload 按目标平台包装消息体：IM 发纯文本，generic 原样发结构体。未知格式按 generic 处理。
func payload(format string, generic any, text string) []byte {
	v := generic
	switch format {
	case "dingtalk":
		v = map[string]any{"msgtype": "text", "text": map[string]string{"content": text}}
	case "feishu":
		v = map[string]any{"msg_type": "text", "content": map[string]string{"text": text}}
	case "wecom":
		v = map[string]any{"msgtype": "text", "text": map[string]string{"content": text}}
	}
	b, _ := json.Marshal(v)
	return b
}

func (n *Notifier) post(ctx context.Context, t Target, m Message) error {
	return send(ctx, n.Client, t.URL, payload(t.Format, m, text(m)))
}

// Text 非 incident 的通知：任务报告、任务失败等。也是 generic 格式的推送体。
type Text struct {
	Title string `json:"title"`
	Body  string `json:"body"`
	Link  string `json:"link,omitempty"`
}

// Webhook 推送任意文本，与 incident 通知共用目标与格式。未配置目标时 Send 什么都不做。
type Webhook struct {
	Settings *Settings
	Client   *http.Client
}

// Send 的 path 是控制台内的相对链接，如 /?session=…，有链接前缀时才拼出来。
func (h *Webhook) Send(ctx context.Context, title, body, path string) error {
	return h.SendTo(ctx, h.Settings.Load(ctx), title, body, path)
}

// SendTo 推到指定目标，供"发送测试"在保存前验证配置。
func (h *Webhook) SendTo(ctx context.Context, target Target, title, body, path string) error {
	if target.URL == "" {
		return nil
	}
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	t := Text{Title: title, Body: body}
	if path != "" && target.LinkBase != "" {
		t.Link = target.LinkBase + path
	}
	full := "【OpenXDR】" + t.Title + "\n" + t.Body
	if t.Link != "" {
		full += "\n" + t.Link
	}
	return send(ctx, client, target.URL, payload(target.Format, t, full))
}

func send(ctx context.Context, client *http.Client, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook 返回 %d", resp.StatusCode)
	}
	return nil
}
