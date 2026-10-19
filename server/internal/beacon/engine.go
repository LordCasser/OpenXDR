package beacon

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
)

const batchLimit = 5000

// Engine 增量读出站连接，内存里给每条外联留最近 Window 的连接时刻；单活运行（cluster.RunLeader）
type Engine struct {
	DB             *ent.Client
	SQL            *sql.DB
	Suppress       *suppress.Store
	LearningPeriod time.Duration
	Window         time.Duration
	Interval       time.Duration

	cursorTs time.Time
	cursorID uuid.UUID
	// quietUntil 之前的事件只学不报：首次上线回放历史时用
	quietUntil time.Time
	flows      map[flowKey]*flowState
	known      map[flowKey]bool
	// 资产接入时间：接入未满学习期的只学不报。不能按基线最早一条算——平时没有规律外联的干净主机
	// 进不了基线，它冒出的第一条心跳恰恰最可疑
	joined map[uuid.UUID]time.Time
}

type flowKey struct {
	asset uuid.UUID
	flow  string
}

type flowState struct {
	conn  Conn
	times []time.Time
	event uuid.UUID
}

func (e *Engine) Run(ctx context.Context) {
	if err := e.start(ctx, time.Now()); err != nil {
		slog.Error("外联心跳检测启动失败", "err", err)
		return
	}
	ticker := time.NewTicker(e.Interval)
	defer ticker.Stop()
	for {
		if err := e.drain(ctx, time.Now()); err != nil {
			slog.Error("外联心跳检测失败", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// start 载入基线。基线为空说明是首次启用：从学习期起点回放库里的历史，只学不报，
// 有历史数据的资产上线即过学习期；否则从一个窗口之前接着看（重复的由基线挡住）
func (e *Engine) start(ctx context.Context, now time.Time) error {
	e.flows, e.known, e.joined = map[flowKey]*flowState{}, map[flowKey]bool{}, map[uuid.UUID]time.Time{}
	rows, err := e.DB.BeaconBaseline.Query().All(ctx)
	if err != nil {
		return err
	}
	for _, b := range rows {
		e.known[flowKey{b.AssetID, b.Flow}] = true
	}
	e.cursorTs = now.Add(-e.Window)
	if len(rows) == 0 {
		e.cursorTs, e.quietUntil = now.Add(-e.LearningPeriod), now
	}
	return nil
}

func (e *Engine) joinedAt(ctx context.Context, asset uuid.UUID) (time.Time, error) {
	if t, ok := e.joined[asset]; ok {
		return t, nil
	}
	a, err := e.DB.Asset.Get(ctx, asset)
	if err != nil {
		return time.Time{}, err
	}
	e.joined[asset] = a.FirstSeen
	return a.FirstSeen, nil
}

// drain 读到追上当前时刻为止。晚到半分钟内的事件留给下一轮，免得游标越过还在写入的事件
func (e *Engine) drain(ctx context.Context, now time.Time) error {
	for {
		n, err := e.batch(ctx, now.Add(-30*time.Second))
		if err != nil || n < batchLimit {
			return err
		}
	}
}

func (e *Engine) batch(ctx context.Context, upTo time.Time) (int, error) {
	rows, err := e.SQL.QueryContext(ctx, `SELECT id, asset_id, ts, raw->'dst_endpoint'->>'ip',
 coalesce(raw->'dst_endpoint'->>'port',''), coalesce(raw->'dst_endpoint'->>'hostname',''),
 coalesce(raw->'process'->>'name',''), coalesce(raw->'container'->>'name',''), raw ? 'platform_command'
FROM events WHERE class_uid=4001 AND source='agent' AND asset_id IS NOT NULL
 AND ts >= $1 AND (ts, id) > ($1, $2) AND ts <= $3 AND raw->'connection_info'->>'direction'='outbound'
ORDER BY ts, id LIMIT $4`, e.cursorTs, e.cursorID, upTo, batchLimit)
	if err != nil {
		return 0, err
	}
	touched := map[flowKey]bool{}
	n := 0
	for rows.Next() {
		var id, asset uuid.UUID
		var ts time.Time
		var ip sql.NullString
		var c Conn
		var commanded bool
		if err := rows.Scan(&id, &asset, &ts, &ip, &c.Port, &c.Host, &c.Process, &c.Container, &commanded); err != nil {
			rows.Close()
			return 0, err
		}
		n++
		e.cursorTs, e.cursorID = ts, id
		c.IP = ip.String
		// 平台指令拉起的连接不进基线也不报，与 UEBA 一致
		if commanded || !Public(c.IP) {
			continue
		}
		k := flowKey{asset, c.Flow()}
		f := e.flows[k]
		if f == nil {
			f = &flowState{}
			e.flows[k] = f
		}
		f.conn, f.event = c, id
		f.times = append(f.times, ts)
		touched[k] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	e.prune(e.cursorTs.Add(-e.Window))
	for k := range touched {
		if f := e.flows[k]; f != nil && !e.known[k] {
			if err := e.observe(ctx, k, f); err != nil {
				return 0, err
			}
		}
	}
	return n, nil
}

// prune 丢掉窗口外的连接时刻，空了的外联整条丢掉，内存随活跃外联数有界
func (e *Engine) prune(before time.Time) {
	for k, f := range e.flows {
		i := 0
		for i < len(f.times) && f.times[i].Before(before) {
			i++
		}
		f.times = f.times[i:]
		if len(f.times) == 0 {
			delete(e.flows, k)
		}
	}
}

// observe 新出现的规律外联：入基线；资产接入已满学习期、且不在首次回放里，才出告警
func (e *Engine) observe(ctx context.Context, k flowKey, f *flowState) error {
	p, ok := Periodic(f.times)
	if !ok {
		return nil
	}
	// 多节点切换时可能有别的实例刚写过，以唯一索引为准：没插进去就不是新的
	var inserted uuid.UUID
	err := e.SQL.QueryRowContext(ctx, `INSERT INTO beacon_baselines(id, asset_id, flow, first_seen) VALUES($1,$2,$3,$4)
ON CONFLICT (asset_id, flow) DO NOTHING RETURNING id`, uuid.Must(uuid.NewV7()), k.asset, k.flow, p.First).Scan(&inserted)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	e.known[k] = true
	if err == sql.ErrNoRows || p.Last.Before(e.quietUntil) {
		return nil
	}
	joined, err := e.joinedAt(ctx, k.asset)
	if err != nil || p.Last.Sub(joined) < e.LearningPeriod {
		return err
	}
	ev, err := e.DB.Event.Get(ctx, f.event)
	if err != nil {
		return err
	}
	var raw map[string]any
	_ = json.Unmarshal(ev.Raw, &raw)
	if e.Suppress != nil && e.Suppress.Suppressed(sigma.RuleBeacon, &k.asset, raw, p.Last) {
		return nil
	}
	detail := f.conn.Describe(p)
	if err := e.DB.Alert.Create().SetTs(p.Last).SetLastTs(p.Last).SetRuleID(sigma.RuleBeacon).SetSeverity(3).
		SetEventID(f.event).SetAssetID(k.asset).SetCount(p.Hits).SetDetail(detail).Exec(ctx); err != nil {
		return err
	}
	slog.Info("新出现的外联心跳", "asset", k.asset, "flow", k.flow, "median", p.Median, "hits", p.Hits)
	return nil
}
