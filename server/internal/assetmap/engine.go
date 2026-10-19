package assetmap

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/event"
	"openxdr/server/internal/triage"
)

const (
	batchLimit = 1000
	cursorKey  = "assetmap.cursor"
	// 首次启用往回补一周的连接，图谱上线就有内容
	backfill = 7 * 24 * time.Hour
	// 超过这么久没再出现的依赖边删掉，与原始事件保留期同量级
	linkTTL = 30 * 24 * time.Hour
	// 标注检查周期：重算事实指纹比对，变了才调模型
	checkEvery = 10 * time.Minute
)

// Engine 集群单活：增量扫描网络与设备清单事件，物化资产画像与依赖边，按需触发 AI 标注。
// 读的是已落库的事件，队列模式与单机直连模式一视同仁。
type Engine struct {
	DB       *ent.Client
	SQL      *sql.DB
	LLM      *triage.LLM
	Interval time.Duration
	// 定时重新标注的周期，0 表示只在事实变化或人工要求时标注
	Refresh time.Duration

	cursor    time.Time
	lastCheck time.Time
	lastPrune time.Time
	// 标注失败的时刻，单活进程内存里记着即可，重启后重试无妨
	failed map[uuid.UUID]time.Time
}

func (e *Engine) Run(ctx context.Context) {
	e.cursor = e.loadCursor(ctx)
	ticker := time.NewTicker(e.Interval)
	defer ticker.Stop()
	for {
		for {
			n, err := e.batch(ctx)
			if err != nil {
				slog.Error("资产图谱批次失败", "err", err)
				break
			}
			if n < batchLimit {
				break
			}
		}
		if time.Since(e.lastPrune) > time.Hour {
			e.lastPrune = time.Now()
			if _, err := e.SQL.ExecContext(ctx, `DELETE FROM asset_links WHERE last_seen < $1`, time.Now().Add(-linkTTL)); err != nil {
				slog.Error("清理过期依赖边失败", "err", err)
			}
		}
		if e.LLM != nil && e.LLM.Enabled() {
			e.annotateDue(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (e *Engine) loadCursor(ctx context.Context) time.Time {
	var raw []byte
	err := e.SQL.QueryRowContext(ctx, `SELECT value FROM settings WHERE id=$1`, cursorKey).Scan(&raw)
	var ts time.Time
	if err == nil && json.Unmarshal(raw, &ts) == nil {
		return ts
	}
	return time.Now().Add(-backfill)
}

type linkKey struct {
	srcIP, dstIP string
	port         int
	proto        string
	process      string
}

type linkAgg struct {
	srcAsset    *uuid.UUID
	count       int64
	first, last time.Time
}

func (e *Engine) batch(ctx context.Context) (int, error) {
	events, err := e.DB.Event.Query().
		Where(event.ClassUIDIn(classNetwork, ClassInventory, ClassSoftware), event.TsGT(e.cursor)).
		Order(ent.Asc(event.FieldTs)).
		Limit(batchLimit).
		All(ctx)
	if err != nil || len(events) == 0 {
		return 0, err
	}
	own, err := e.assetIPs(ctx)
	if err != nil {
		return 0, err
	}
	names, err := e.processNames(ctx, events)
	if err != nil {
		return 0, err
	}
	managed := map[netip.Addr]bool{}
	for _, ips := range own {
		for _, ip := range ips {
			managed[ip] = true
		}
	}

	links := map[linkKey]*linkAgg{}
	type snapshot struct {
		ts        time.Time
		listening []Listener
		cloud     *Cloud
	}
	inventories := map[uuid.UUID]snapshot{}
	type softwareSnap struct {
		ts time.Time
		sw *Software
	}
	softwares := map[uuid.UUID]softwareSnap{}
	for _, ev := range events {
		if ev.ClassUID == ClassSoftware {
			if sw, ok := software(ev.Raw); ok && ev.AssetID != nil {
				softwares[*ev.AssetID] = softwareSnap{ev.Ts, sw}
			}
			continue
		}
		if ev.ClassUID == ClassInventory {
			if ev.AssetID != nil {
				l, c := inventory(ev.Raw)
				inventories[*ev.AssetID] = snapshot{ev.Ts, l, c}
			}
			continue
		}
		tuple := ""
		if ev.ConnTuple != nil {
			tuple = *ev.ConnTuple
		}
		c, ok := connOf(ev.Raw, tuple)
		if !ok {
			continue
		}
		srcAsset, process := ev.AssetID, c.process
		var ownIPs []netip.Addr
		if ev.AssetID != nil {
			ownIPs = own[*ev.AssetID]
		}
		if c.inbound {
			// 入站只补发起方未纳管的那部分：发起方纳管时它自己的出站已经记过这条依赖。
			// 只认连到宿主机自己地址上的：宿主机上容器的服务（docker 网桥、LXC）不是这台资产的服务。
			// 发起方由地址解析，进程是本机服务端，不是发起方，不记
			if managed[c.src] || !slices.Contains(ownIPs, c.dst) || !dependency(c, nil) {
				continue
			}
			srcAsset, process = nil, ""
		} else {
			if !dependency(c, ownIPs) {
				continue
			}
			// 新版 agent 随连接带进程名；旧版只有 GUID，回查同一进程的启动事件
			if process == "" && ev.ProcessGUID != nil {
				process = names[*ev.ProcessGUID]
			}
		}
		k := linkKey{c.src.String(), c.dst.String(), c.port, c.proto, process}
		agg := links[k]
		if agg == nil {
			agg = &linkAgg{srcAsset: srcAsset, first: ev.Ts}
			links[k] = agg
		}
		agg.count++
		agg.last = ev.Ts
	}

	cursor := events[len(events)-1].Ts
	tx, err := e.SQL.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	for k, a := range links {
		if _, err := tx.ExecContext(ctx, `INSERT INTO asset_links
  (id, src_ip, src_asset_id, dst_ip, dst_port, proto, process, count, first_seen, last_seen)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT (src_ip, dst_ip, dst_port, proto, process) DO UPDATE SET
  count = asset_links.count + EXCLUDED.count,
  first_seen = LEAST(asset_links.first_seen, EXCLUDED.first_seen),
  last_seen = GREATEST(asset_links.last_seen, EXCLUDED.last_seen),
  src_asset_id = COALESCE(EXCLUDED.src_asset_id, asset_links.src_asset_id)`,
			uuid.Must(uuid.NewV7()), k.srcIP, a.srcAsset, k.dstIP, k.port, k.proto, k.process, a.count, a.first, a.last); err != nil {
			return 0, err
		}
	}
	for id, s := range softwares {
		sw, _ := json.Marshal(s.sw)
		if _, err := tx.ExecContext(ctx, `UPDATE assets SET software=$2::jsonb, software_at=$3
WHERE id=$1 AND (software_at IS NULL OR software_at < $3)`, id, string(sw), s.ts); err != nil {
			return 0, err
		}
	}
	for id, s := range inventories {
		listening, _ := json.Marshal(s.listening)
		var cloud any
		if s.cloud != nil {
			b, _ := json.Marshal(s.cloud)
			cloud = string(b)
		}
		// 只接受比已物化的更新的快照，乱序到达的旧快照不回滚状态
		if _, err := tx.ExecContext(ctx, `UPDATE assets SET listening=$2::jsonb, cloud=$3::jsonb, inventory_at=$4
WHERE id=$1 AND (inventory_at IS NULL OR inventory_at < $4)`, id, string(listening), cloud, s.ts); err != nil {
			return 0, err
		}
	}
	value, _ := json.Marshal(cursor)
	if _, err := tx.ExecContext(ctx, `INSERT INTO settings (id, value, updated_at) VALUES ($1, $2::jsonb, now())
ON CONFLICT (id) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, cursorKey, string(value)); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	e.cursor = cursor
	return len(events), nil
}

// assetIPs 资产登记的地址，判断连接是否发自宿主机本身
func (e *Engine) assetIPs(ctx context.Context) (map[uuid.UUID][]netip.Addr, error) {
	assets, err := e.DB.Asset.Query().All(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID][]netip.Addr, len(assets))
	for _, a := range assets {
		out[a.ID] = parseIPs(a.IPAddrs)
	}
	return out, nil
}

// processNames 网络事件只带进程 GUID，名字从同一进程的启动事件里取
func (e *Engine) processNames(ctx context.Context, events []*ent.Event) (map[uuid.UUID]string, error) {
	seen := map[uuid.UUID]bool{}
	var ids []string
	for _, ev := range events {
		if ev.ClassUID == classNetwork && ev.ProcessGUID != nil && !seen[*ev.ProcessGUID] {
			seen[*ev.ProcessGUID] = true
			ids = append(ids, ev.ProcessGUID.String())
		}
	}
	out := map[uuid.UUID]string{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := e.SQL.QueryContext(ctx, `SELECT DISTINCT ON (process_guid) process_guid, coalesce(raw->'process'->>'name', '')
FROM events WHERE process_guid = ANY($1::uuid[]) AND class_uid = 1007`, "{"+strings.Join(ids, ",")+"}")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out[id] = clean(name, 64)
	}
	return out, rows.Err()
}
