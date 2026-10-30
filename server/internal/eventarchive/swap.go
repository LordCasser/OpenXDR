package eventarchive

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/eventpart"
)

// 阶段 C：单日分区切换与恢复。
//
// 阶段 A 把候选事件编码进冷块，但仍留在 events 里；阶段 C 才真正把它们从热表移走：
// 某个 **日分区** 被重建成「被钉住的 + 不属于本 run 类别/来源的」行，其余行随旧分区消失，
// 于是同一批事件只剩冷块里那一份。这是整个冷归档唯一会删数据的环节，因此：
//
//   - 先 plan（纯只读）给人核对，再 swap（-confirm）；
//   - swap 只接受 verified 的 run，且要求「要移出的条数」恰好等于这个 run 落在该日冷块里的条数，
//     对不上就拒绝——差额通常来自单条超过 MaxEventBytes 未进冷块的事件，删了就是丢数据；
//   - 分区重建由 eventpart.RewriteDay 在单个事务里完成，失败回滚，原分区原样保留；
//   - restore 把该日该 run 的冷事件按块批量物化回 events（幂等），用于回滚。
//
// 保留口径与归档口径严格互补，且两边共用同一份谓词（scopePredicate）：
// 归档 = 属于 run 的 (class_uid, source) 且未被钉住；保留 = 被钉住 或 不属于该 (class_uid, source)。

// SwapPlan 是一天的切换计划。四个计数互斥且覆盖该日分区的全部行：
// Archived + KeepPinned + KeepOther == Total。只读，不写任何东西。
type SwapPlan struct {
	Day        time.Time // UTC 日
	Archived   int64     // 该日、该 run 覆盖的类别/来源、且未被 pin 的行数（将被移出热表）
	KeepPinned int64     // 该日被 pin 保护的行数（无论类别/来源）
	KeepOther  int64     // 该日其它类别/来源的行数
	Total      int64     // 该日分区当前总行数
}

// Plan 只读地统计某天的切换计划，用于人工核对。不写任何东西，也不改 run。
// 拒绝条件只有「结构上没法切」：run 不存在、day 不在 run 的日期范围内、该日没有独立日分区。
// 状态与条数是否满足切换条件由 Swap 判定（plan 的职责是如实报数，不是拦住运维看一眼）。
func Plan(ctx context.Context, db *sql.DB, runID uuid.UUID, day time.Time) (SwapPlan, error) {
	run, err := LoadRun(ctx, db, runID)
	if err != nil {
		return SwapPlan{}, err
	}
	return planDay(ctx, db, run, day)
}

// planDay 是 Plan 的主体，Swap 复用同一份统计，保证「核对的」与「执行的」是同一套口径。
func planDay(ctx context.Context, db *sql.DB, run Run, day time.Time) (SwapPlan, error) {
	p := SwapPlan{Day: dayStart(day)}
	if err := checkDayInRun(run, p.Day); err != nil {
		return p, err
	}
	scope, err := scopePredicate(run)
	if err != nil {
		return p, err
	}
	partition := eventpart.DailyName(p.Day)
	ok, err := relExists(ctx, db, partition)
	if err != nil {
		return p, err
	}
	if !ok {
		return p, noPartitionErr(ctx, db, p.Day)
	}
	// 四个桶互斥且穷尽：pin 优先，其次看类别/来源是否在 run 口径内。
	query := fmt.Sprintf(`SELECT count(*),
 count(*) FILTER (WHERE %[1]s),
 count(*) FILTER (WHERE NOT (%[1]s) AND (%[2]s)),
 count(*) FILTER (WHERE NOT (%[1]s) AND NOT (%[2]s))
 FROM %[3]s`, pinnedPredicate, scope, partition)
	if err := db.QueryRowContext(ctx, query).Scan(&p.Total, &p.KeepPinned, &p.Archived, &p.KeepOther); err != nil {
		return p, fmt.Errorf("统计 %s 的各类计数: %w", partition, err)
	}
	if sum := p.Archived + p.KeepPinned + p.KeepOther; sum != p.Total {
		// 三个桶由互斥的 FILTER 定义，结构上必然等于 total；留一道断言防止以后改口径改漏
		return p, fmt.Errorf("%s 的计数不自洽：归档 %d + 钉住 %d + 其它 %d = %d，分区共 %d 行",
			partition, p.Archived, p.KeepPinned, p.KeepOther, sum, p.Total)
	}
	return p, nil
}

// swapTestHook 只用于测试：非 nil 时在「预检已完成、重写事务未开始」的确切位置回调，
// 让测试能在检查与加锁之间确定性插入并发写入。生产恒为 nil，零行为差异。
var swapTestHook func(stage string) // stage == "prechecks_done"

// Swap 在计划核对通过后重建该日分区，只保留「被 pin 的 + 非归档类别/来源」的行。
//
// 前置条件（任一不满足即拒绝，且此时**一个字节都没动**）：
//   - run 存在且 status=verified（没对拍通过的归档不能作为删除依据）；
//   - day 在 run 的 DayFrom..DayTo 内；
//   - 该日有独立日分区（行在默认分区时报错，要求先 EnsureDays，不去默认分区搬行）；
//   - Plan 的 Archived > 0（没有要移出的行就不该重建分区）；
//   - 该日冷块里的条数**恰好等于** Archived：少一条都说明有行会被删而没有冷副本。
//
// 重建本身由 eventpart.RewriteDay 在单个事务里完成（建暂存表 → 复制 → 核对 → DETACH/DROP/
// RENAME/ATTACH），失败整体回滚，原分区完好。切换后把计划与结果写进 run 的 detail.swapped，
// 不改 status。
func Swap(ctx context.Context, db *sql.DB, runID uuid.UUID, day time.Time) (SwapPlan, error) {
	run, err := LoadRun(ctx, db, runID)
	if err != nil {
		return SwapPlan{}, err
	}
	if run.Status != StatusVerified {
		return SwapPlan{}, fmt.Errorf("run %s 的状态是 %s，只有 verified 的 run 才能切换分区（先跑 verify）", runID, run.Status)
	}
	p, err := planDay(ctx, db, run, day)
	if err != nil {
		return p, err
	}
	if p.Archived == 0 {
		return p, fmt.Errorf("%s 没有被 run %s 归档的事件（Archived=0），无需切换", p.Day.Format(time.DateOnly), runID)
	}
	cold, err := coldCount(ctx, db, runID, p.Day)
	if err != nil {
		return p, err
	}
	if cold != p.Archived {
		return p, fmt.Errorf("%s 待移出 %d 条，run %s 在该日的冷块里只有 %d 条，"+
			"两者必须相等才允许删除（差额通常来自单条超过 %d 字节未进冷块的事件，或对拍之后 events 有变化）：拒绝执行",
			p.Day.Format(time.DateOnly), p.Archived, runID, cold, MaxEventBytes)
	}
	keep, err := keepSelect(p.Day, run)
	if err != nil {
		return p, err
	}
	if swapTestHook != nil {
		swapTestHook("prechecks_done")
	}
	kept, dropped, err := eventpart.RewriteDay(ctx, db, p.Day, keep)
	if err != nil {
		return p, fmt.Errorf("重建日分区 %s: %w", eventpart.DailyName(p.Day), err)
	}
	// 事务里的 keepSelect 与这里的计划是同一口径，正常必然相等；不等说明 Plan 之后 events 变了
	// （迟到写入、钉住关系变化、行被清理），此时分区已经按实际口径重建，如实报出来。
	if kept != p.KeepPinned+p.KeepOther || dropped != p.Archived {
		actual := SwapPlan{Day: p.Day, Archived: dropped, Total: kept + dropped}
		note := fmt.Sprintf("计划保留 %d 条 / 移出 %d 条（共 %d），实际保留 %d 条 / 移出 %d 条",
			p.KeepPinned+p.KeepOther, p.Archived, p.Total, kept, dropped)
		recordErr := recordSwap(ctx, db, runID, actual, note)
		msg := fmt.Sprintf("%s 的分区已重建，但结果与计划不符：%s。分区已按实际口径切换，请重跑 verify 核对", p.Day.Format(time.DateOnly), note)
		if recordErr != nil {
			return p, fmt.Errorf("%s；另外写 detail.swapped 失败: %w", msg, recordErr)
		}
		return p, errors.New(msg)
	}
	if err := recordSwap(ctx, db, runID, p, ""); err != nil {
		// 分区已经切换成功，只是记账失败：如实说明，不假装没发生
		return p, err
	}
	return p, nil
}

// Restore 把该日该 run 的冷事件全部物化回 events（幂等），返回实际插入的行数。
// 已经存在于 events 的事件不计入——重复调用第二次返回 0，用于回滚一次 Swap。
//
// 按块批量物化（P1）：每块只 load 一次、Decode 一次、check 一次，随后在**单个事务**里
// 用一条 typed unnest 的 INSERT 把整块写回。不再逐事件走 Materialize → Locate：
// 那是 O(n × 块数) 的重复定位与重复解压（历史实测 24.9 行/秒），单条物化入口 Materialize
// 保留给其它调用方。不经过检测器、不产告警、不改任何派生表，也不回写冷块。
//
// 失败语义是**块级原子**：当前块解码、校验或写入失败时只回滚该块，此前已提交的块保留；
// 此时返回 (已插入数, 错误)，两者同时有效（部分完成）。错误带块 id 与原因。重跑靠
// events 的主键幂等继续（已恢复的行被 ON CONFLICT DO NOTHING 跳过），不需要进度账本。
func Restore(ctx context.Context, db *sql.DB, runID uuid.UUID, day time.Time) (int64, error) {
	run, err := LoadRun(ctx, db, runID)
	if err != nil {
		return 0, err
	}
	d := dayStart(day)
	if err := checkDayInRun(run, d); err != nil {
		return 0, err
	}
	ids, err := dayChunkIDs(ctx, db, runID, d)
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, fmt.Errorf("run %s 在 %s 没有冷块，没有可还原的事件", runID, d.Format(time.DateOnly))
	}
	src := &sqlSource{db: db}
	var restored int64
	for _, id := range ids {
		ch, err := src.load(ctx, id)
		if err != nil {
			return restored, err
		}
		events, err := ch.Block.Decode()
		if err != nil {
			return restored, fmt.Errorf("解码冷块 %s（seq %d，%s/%s）: %w",
				ch.ID, ch.Seq, ch.Day.Format(time.DateOnly), ch.Source, err)
		}
		if err := ch.check(events); err != nil {
			return restored, fmt.Errorf("冷块 %s（seq %d）内容与头部不符: %w", ch.ID, ch.Seq, err)
		}
		inserted, err := insertEvents(ctx, db, events)
		if err != nil {
			return restored, fmt.Errorf("写入冷块 %s（seq %d，%s/%s）的 %d 条事件: %w",
				ch.ID, ch.Seq, ch.Day.Format(time.DateOnly), ch.Source, len(events), err)
		}
		restored += inserted
	}
	return restored, nil
}

// insertEvents 在单个事务里把一块已解码并通过校验的事件批量插回 events。
//
// 列映射与 Materialize 的单条 INSERT 相同（同样 10 列、同样 ON CONFLICT DO NOTHING、
// 不覆盖已存在的行），区别只在承载方式：一条固定 10 个参数的 INSERT ... SELECT，
// 参数个数与块内条数无关，不会把最大块展开成 N×10 个占位符。
//
//   - 可空列用指针元素类型（[]*uuid.UUID / []*string）：nil 元素编码为 SQL NULL，
//     与 Event 里的指针一一对应，不会把 NULL 折成零值或空串；
//   - raw 以 text[] 传入、逐元素 ::jsonb：块里存的本来就是 events.raw 的 jsonb 文本表示，
//     转回 jsonb 与单条物化走同一条解析路径；不合法 JSON 会让整块失败回滚，而不是静默入库；
//   - RowsAffected 就是实际插入数，已存在的行被 ON CONFLICT DO NOTHING 跳过。
//
// 失败时本块整体回滚（包括约束失败，如 asset_id 指向已删除的资产）。
func insertEvents(ctx context.Context, db *sql.DB, events []Event) (int64, error) {
	n := len(events)
	cols := restoreColumns{
		ids:     make([]uuid.UUID, n),
		ts:      make([]time.Time, n),
		classes: make([]int64, n),
		sources: make([]string, n),
		assets:  make([]*uuid.UUID, n),
		procs:   make([]*uuid.UUID, n),
		parents: make([]*uuid.UUID, n),
		users:   make([]*string, n),
		conns:   make([]*string, n),
		raws:    make([]string, n),
	}
	for i, e := range events {
		cols.ids[i], cols.ts[i], cols.classes[i], cols.sources[i] = e.ID, e.Ts, e.ClassUID, e.Source
		cols.assets[i], cols.procs[i], cols.parents[i] = e.AssetID, e.ProcessGUID, e.ParentProcessGUID
		cols.users[i], cols.conns[i] = e.Username, e.ConnTuple
		cols.raws[i] = string(e.Raw)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("开始事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `INSERT INTO events
 (`+eventColumns+`)
 SELECT u.id, u.ts, u.class_uid, u.source, u.asset_id, u.process_guid, u.parent_process_guid,
        u.username, u.conn_tuple, u.raw::jsonb
 FROM unnest($1::uuid[], $2::timestamptz[], $3::bigint[], $4::text[], $5::uuid[], $6::uuid[],
             $7::uuid[], $8::text[], $9::text[], $10::text[])
      AS u(id, ts, class_uid, source, asset_id, process_guid, parent_process_guid,
           username, conn_tuple, raw)
 ON CONFLICT DO NOTHING`,
		cols.ids, cols.ts, cols.classes, cols.sources, cols.assets, cols.procs,
		cols.parents, cols.users, cols.conns, cols.raws)
	if err != nil {
		return 0, fmt.Errorf("批量插入 %d 行: %w", n, err)
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("统计批量插入 %d 行的结果: %w", n, err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("提交 %d 行: %w", n, err)
	}
	return inserted, nil
}

// restoreColumns 是 insertEvents 的并行列缓冲：一块一分配，块内逐事件填一行。
// 列清单本身复用 scan.go 的 eventColumns 常量，冷块读取与写回是同一组列。
type restoreColumns struct {
	ids     []uuid.UUID
	ts      []time.Time
	classes []int64
	sources []string
	assets  []*uuid.UUID
	procs   []*uuid.UUID
	parents []*uuid.UUID
	users   []*string
	conns   []*string
	raws    []string
}

// pinnedPredicate 是 PinnedIDs 的 IN 形式：被钉住的事件既不在归档口径里，也一定被保留。
const pinnedPredicate = `id IN (` + eventpart.PinnedIDs + `)`

// scopePredicate 把 run 的类别与来源写成 SQL 谓词。Plan 的统计与 keepSelect 的保留口径
// 都用它，两者因此是同一份字面量，而不是各写一遍后靠注释保证一致。
//
// 值都来自 run 行本身（构建时从 events 里数出来的类别与来源），仍按 SQL 字面量转义：
// 单引号写两遍，类别是整数直接格式化。
func scopePredicate(run Run) (string, error) {
	if len(run.Classes) == 0 {
		return "", fmt.Errorf("run %s 没有类别口径", run.ID)
	}
	if len(run.Sources) == 0 {
		return "", fmt.Errorf("run %s 没有来源口径（范围里没有事件时不会有冷块，也没什么可切）", run.ID)
	}
	classes := make([]string, len(run.Classes))
	for i, c := range run.Classes {
		classes[i] = strconv.Itoa(c)
	}
	sources := make([]string, len(run.Sources))
	for i, s := range run.Sources {
		sources[i] = "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	return fmt.Sprintf(`class_uid = ANY(ARRAY[%s]::bigint[]) AND source = ANY(ARRAY[%s]::text[])`,
		strings.Join(classes, ","), strings.Join(sources, ",")), nil
}

// keepSelect 是 RewriteDay 的保留口径：被钉住的 或 不属于本 run 类别/来源的行留下，
// 其余（= 被归档的那些）移出热表。与归档口径严格互补，两个集合相加必然等于分区行数。
func keepSelect(day time.Time, run Run) (string, error) {
	scope, err := scopePredicate(run)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`SELECT id FROM %s WHERE %s OR NOT (%s)`,
		eventpart.DailyName(day), pinnedPredicate, scope), nil
}

// coldCount 是这个 run 落在某一天的冷块事件条数（块声明的 event_count 之和，不解压）。
func coldCount(ctx context.Context, db *sql.DB, runID uuid.UUID, day time.Time) (int64, error) {
	var n int64
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(sum(event_count), 0) FROM event_archive_chunks
 WHERE run_id = $1 AND day = $2`, runID, day).Scan(&n); err != nil {
		return 0, fmt.Errorf("统计 run %s 在 %s 的冷块: %w", runID, day.Format(time.DateOnly), err)
	}
	return n, nil
}

// dayChunkIDs 按 seq 顺序取某日冷块 id（只读元数据，不解压）。
func dayChunkIDs(ctx context.Context, db *sql.DB, runID uuid.UUID, day time.Time) ([]uuid.UUID, error) {
	rows, err := db.QueryContext(ctx, `SELECT id FROM event_archive_chunks
 WHERE run_id = $1 AND day = $2 ORDER BY seq`, runID, day)
	if err != nil {
		return nil, wrapErr(err, "列出 run %s 在 %s 的冷块", runID, day.Format(time.DateOnly))
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, wrapErr(err, "读取冷块 id")
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapErr(err, "列出 run %s 在 %s 的冷块", runID, day.Format(time.DateOnly))
	}
	return ids, nil
}

// checkDayInRun 确认 day 落在 run 的 UTC 日闭区间内：范围外的一天没有「本 run 的归档」可言。
func checkDayInRun(run Run, day time.Time) error {
	from, to := dayStart(run.DayFrom), dayStart(run.DayTo)
	if day.Before(from) || day.After(to) {
		return fmt.Errorf("%s 不在 run %s 的 %s..%s 范围内",
			day.Format(time.DateOnly), run.ID, from.Format(time.DateOnly), to.Format(time.DateOnly))
	}
	return nil
}

// relExists 报告表/视图是否存在（只查目录，不碰数据）。
func relExists(ctx context.Context, db *sql.DB, name string) (bool, error) {
	var ok bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&ok); err != nil {
		return false, fmt.Errorf("查找 %s: %w", name, err)
	}
	return ok, nil
}

// noPartitionErr 说明「该日没有独立日分区」并给出默认分区里的行数：
// 这类日子必须先 EnsureDays 建好日分区，本流程不会自己去默认分区搬行。
func noPartitionErr(ctx context.Context, db *sql.DB, day time.Time) error {
	msg := fmt.Sprintf("%s 没有独立日分区 %s", day.Format(time.DateOnly), eventpart.DailyName(day))
	var stray int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM `+eventpart.DefaultName+` WHERE ts >= $1 AND ts < $2`,
		day, day.AddDate(0, 0, 1)).Scan(&stray); err == nil && stray > 0 {
		msg += fmt.Sprintf("（该日有 %d 行在默认分区 %s）", stray, eventpart.DefaultName)
	}
	return errors.New(msg + "：先跑 EnsureDays / 分区预建把这一天的独立日分区建出来再重试，本流程不去默认分区搬行")
}

// swapDetail 是写进 run 的 detail.swapped 的那段 JSON：一天的实际切换结果。
type swapDetail struct {
	Day        string `json:"day"`
	Archived   int64  `json:"archived"`
	KeepPinned int64  `json:"keep_pinned"`
	KeepOther  int64  `json:"keep_other"`
	Total      int64  `json:"total"`
	At         string `json:"at"`
	Note       string `json:"note,omitempty"`
}

// recordSwap 把切换结果合并进 run 的 detail（键 swapped），不改 status。
func recordSwap(ctx context.Context, db *sql.DB, runID uuid.UUID, p SwapPlan, note string) error {
	detail := swapDetail{
		Day: p.Day.Format(time.DateOnly), Archived: p.Archived, KeepPinned: p.KeepPinned,
		KeepOther: p.KeepOther, Total: p.Total, At: time.Now().UTC().Format(time.RFC3339), Note: note,
	}
	encoded, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("序列化 run %s 的 detail.swapped: %w", runID, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE event_archive_runs
 SET detail = jsonb_set(COALESCE(detail, '{}'::jsonb), '{swapped}', $2::jsonb, true) WHERE id = $1`,
		runID, encoded); err != nil {
		return fmt.Errorf("run %s 的分区已切换，但写 detail.swapped 失败: %w", runID, err)
	}
	return nil
}
