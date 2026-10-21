package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/intel"
	"openxdr/server/internal/suricata"
)

// SuricataEnvelope 不把 EVE 中的任意字段提升为平台身份、进程或指令标记。
// 未归属告警按发起端地址关联，去重按地址对累计；端口不参与，否则每条新连接都自成告警。
func SuricataEnvelope(origin suricata.Origin, event suricata.Event) Envelope {
	source := origin.GroupID.String() + "|" + origin.Observer
	scope := source + "|" + event.Attacker()
	raw, _ := json.Marshal(map[string]any{
		"metadata":     map[string]any{"product": map[string]any{"name": "Suricata"}, "observer": origin.Observer, "group_id": origin.GroupID, "suricata_scope": scope},
		"src_endpoint": map[string]any{"ip": event.SrcIP, "port": event.SrcPort},
		"dst_endpoint": map[string]any{"ip": event.DestIP, "port": event.DestPort},
		"suricata":     event.Raw,
	})
	return Envelope{
		Version: EnvelopeVersion, ID: StableID("suricata", origin.GroupID.String(), origin.Observer, string(event.Raw)),
		PartitionKey: "suricata|" + scope, Timestamp: event.Time, ClassUID: 2004, Source: "suricata",
		ConnTuple: event.ConnTuple(), Raw: raw, Suricata: &origin,
		FingerprintSuffix: "|" + source + "|" + event.SrcIP + ">" + event.DestIP,
	}
}

// suricataHit 在消费事务内重新核对当前组与资产，避免排队期间资产转组后仍按旧归属落库。
// 只有接收时距事件不超过五分钟才按当前资产观测归属；平台自身的队列积压不算迟到，
// 历史导入没有 IP 租约可查，不猜旧事件归属。
// 规则标了 target 只归属该端；否则每端各自唯一匹配一台资产即归属，两端都是资产时拆成两份证据。
func suricataHit(ctx context.Context, tx *sql.Tx, e Envelope) ([]Envelope, *intel.Hit, error) {
	if e.Source != "suricata" {
		return []Envelope{e}, nil, nil
	}
	var raw struct {
		EVE json.RawMessage `json:"suricata"`
	}
	if err := json.Unmarshal(e.Raw, &raw); err != nil {
		return nil, nil, err
	}
	event, err := suricata.Parse(raw.EVE)
	if err != nil {
		return nil, nil, err
	}
	if !event.Time.Equal(e.Timestamp) || e.ClassUID != 2004 || event.ConnTuple() != e.ConnTuple {
		return nil, nil, fmt.Errorf("Suricata 信封与原始证据不一致")
	}
	hit := &intel.Hit{RuleID: event.RuleID(), Severity: event.Severity(), Detail: fmt.Sprintf("%s（Suricata gid=%d sid=%d rev=%d）", event.Alert.Signature, event.Alert.GID, event.Alert.SID, event.Alert.Rev)}
	e.AssetID, e.AssetOS = nil, ""
	if delta := e.Suricata.Received.Sub(e.Timestamp); delta < -5*time.Minute || delta > 5*time.Minute {
		return []Envelope{e}, hit, nil
	}
	ends := []string{event.SrcIP, event.DestIP}
	if event.Alert.Target != nil {
		ends = []string{event.Alert.Target.IP}
	}
	var out []Envelope
	for i, ip := range ends {
		id, os, err := suricataAsset(ctx, tx, e.Suricata.GroupID, ip, event.Time)
		if err != nil {
			return nil, nil, err
		}
		if id == nil || slices.ContainsFunc(out, func(o Envelope) bool { return *o.AssetID == *id }) {
			continue
		}
		item := e
		item.AssetID, item.AssetOS, item.PartitionKey = id, os, id.String()
		if i > 0 {
			// 目的端证据用派生的稳定 ID，重传仍幂等
			item.ID = StableID("suricata-dest", e.ID.String())
		}
		out = append(out, item)
	}
	if len(out) == 0 {
		return []Envelope{e}, hit, nil
	}
	return out, hit, nil
}

// suricataAsset 该地址在组内恰好对应一台事件时刻在线的资产才返回；重复 IP 不猜。
func suricataAsset(ctx context.Context, tx *sql.Tx, group uuid.UUID, ip string, ts time.Time) (*uuid.UUID, string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, COALESCE(os,'') FROM assets
WHERE group_id=$1 AND ip_addrs ? $2
AND first_seen <= $3 AND last_seen >= $3::timestamptz - interval '5 minutes'
FOR SHARE`, group, ip, ts)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var id uuid.UUID
	var os string
	count := 0
	for rows.Next() {
		if err := rows.Scan(&id, &os); err != nil {
			return nil, "", err
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if count != 1 {
		return nil, "", nil
	}
	return &id, os, nil
}
