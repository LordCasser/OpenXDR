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
// 某个 **日分区** 被重建成「被钉住的 + 不属于本 run 类别/来源的 + **没有冷副本的**」行，
// 其余行随旧分区消失，于是同一批事件只剩冷块里那一份。这是整个冷归档唯一会删数据的环节，
// 因此删除依据不靠事务外的计数（P0 已实测：计数抵消与检查后写入都会静默丢行），而是：
//
//   - 先 plan（纯只读）给人核对——它是估计值，不是冻结快照；
//   - swap 只接受 verified 的 run；保留口径 keepSelect 自带「不在本 run 的 locator 里 → 保留」，
//     shadow 之后到达、或单条超过 MaxEventBytes 没进冷块的行自动留热，不再要求整日
//     计数恰好相等；
//   - 分区重建由 eventpart.RewriteDayGuarded 在单个事务里完成，锁内、删除前跑
//     swapVerify 的四步集合校验（见下），失败整体回滚，原分区原样保留；
//   - 分区替换与 run.detail 的逐日记录（detail.days.<day>）同一事务提交；
//   - restore 把该日该 run 的冷事件按块批量物化回 events（幂等），用于回滚。
//
// 保留口径与归档口径共用同一份谓词（scopePredicate）：归档 = 属于 run 的 (class_uid, source)
// 且未被钉住；保留 = 被钉住 或 不属于该 (class_uid, source) 或 没有本 run 的冷副本。

// SwapPlan 是一天的切换计划。四个计数互斥且覆盖该日分区的全部行：
// Archived + KeepPinned + KeepOther == Total。只读，不写任何东西。
type SwapPlan struct {
	Day        time.Time // UTC 日
	Archived   int64     // 该日、该 run 覆盖的类别/来源、且未被 pin 的行数（事务外估计，可能留热）
	KeepPinned int64     // 该日被 pin 保护的行数（无论类别/来源）
	KeepOther  int64     // 该日其它类别/来源的行数
	Total      int64     // 该日分区当前总行数

	// Guard 是 P4 切换闸门的只读评估（min-age 有效下限 + 消费者追平）。
	// Plan 与 Swap 都会填：Plan 带给人核对（不据此拒绝），Swap 据此拒绝。
	// Swap 因闸门拒绝时返回的 SwapPlan 也带着它，错误信息与报告同源。
	Guard *GuardReport

	// Kept / Dropped 是 Swap 执行后事务内实测的保留/移出数；Plan（只读）恒为零值。
	// 与上面四个估计值可能不同：没有冷副本的行（超大、shadow 之后到达）按事务内核对留热。
	Kept    int64
	Dropped int64
}

// Plan 只读地统计某天的切换计划，用于人工核对。不写任何东西，也不改 run。
// 拒绝条件只有「结构上没法切」：run 不存在、day 不在 run 的日期范围内、该日没有独立日分区。
// 状态与条数是否满足切换条件由 Swap 判定（plan 的职责是如实报数，不是拦住运维看一眼）；
// P4 的切换闸门（min-age / 消费者追平）在这里只评估并附在返回值 Guard 上，不拒绝——
// 是否可切与原因给人看，拦截发生在 Swap。
func Plan(ctx context.Context, db *sql.DB, runID uuid.UUID, day time.Time) (SwapPlan, error) {
	run, err := LoadRun(ctx, db, runID)
	if err != nil {
		return SwapPlan{}, err
	}
	p, err := planDay(ctx, db, run, day)
	if err != nil {
		return p, err
	}
	report, err := Guard(ctx, db, run, p.Day)
	if err != nil {
		return p, err
	}
	p.Guard = &report
	return p, nil
}

// planDay 是 Plan 的主体，Swap 复用同一份统计，保证「核对的」与「执行的」是同一套口径。
func planDay(ctx context.Context, db *sql.DB, run Run, day time.Time) (SwapPlan, error) {
	p := SwapPlan{Day: dayStart(day)}
	if err := checkDayInRun(run, p.Day); err != nil {
		return p, err
	}
	scope, err := scopePredicate(run, "e.")
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
	// 这是对计划时刻的估计（P3 起不作为删除依据）：执行时没有冷副本的行会留热。
	query := fmt.Sprintf(`SELECT count(*),
 count(*) FILTER (WHERE %[1]s),
 count(*) FILTER (WHERE NOT (%[1]s) AND (%[2]s)),
 count(*) FILTER (WHERE NOT (%[1]s) AND NOT (%[2]s))
 FROM %[3]s e`, pinnedPredicate, scope, partition)
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

// swapTestHook 只用于测试：非 nil 时在切换流程的固定阶段回调，返回错误即在该位置中止/回滚，
// 用于确定性注入并发写入与故障。生产恒为 nil，零行为差异。阶段值：
//   - "prechecks_done"：事务外预检完成、重写事务未开始（检查与加锁之间的窗口），tx 为 nil；
//   - "after_copy" / "after_indexes" / "before_replace" / "after_record"：重写事务内
//     （eventpart.RewriteDayGuarded 的注入点，eventpart 不感知本包），tx 非空。
var swapTestHook func(stage string, tx *sql.Tx) error

// Swap 在计划核对通过后重建该日分区，只保留「被 pin 的 + 非归档类别/来源的 + 没有冷副本的」行。
//
// 前置条件（任一不满足即拒绝，且此时**一个字节都没动**）：
//   - run 存在且 status=verified（没对拍通过的归档不能作为删除依据）；
//   - day 在 run 的 DayFrom..DayTo 内；
//   - 该日有独立日分区（行在默认分区时报错，要求先 EnsureDays，不去默认分区搬行）；
//   - Plan 的 Archived > 0（事务外快路径：口径内连一个候选都没有）；
//   - P4 切换闸门（事务外预检，Guard）：日结束不早于「有效下限 = max(min-age, temporal
//     安全边界, 适用的消费者回读窗口)」之前，且口径相交的消费者都有越过待切日的持久进度
//     （unknown 拒绝）。拒绝信息带日结束时间、下限数值、贡献最大值的来源与各消费者原因。
//
// 删除依据完全由重写事务内的集合校验承担（swapVerify，在 SHARE 锁内、删除前执行），
// 事务外的 coldCount 只作警告性预检：与 Archived 不相等（超大、shadow 之后到达的行留热）
// 不再拒绝执行，差额写进 detail.days 的 note。事务内没有可删行时返回「无需切换」且不重建分区。
//
// 返回的 SwapPlan 四个计数是事务外的估计值（Plan 同口径）；Kept/Dropped 是事务内实测结果。
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
	// P4 闸门（事务外预检的一部分：任何写入之前）。结构检查（分区存在、口径内有候选）
	// 在前，闸门在后——闸门只对「本来能切」的日子发表意见。
	report, err := Guard(ctx, db, run, p.Day)
	if err != nil {
		return p, err
	}
	p.Guard = &report
	if !report.Allow {
		return p, report.refusal()
	}
	// 警告性预检：不再作为删除依据，只把差额记进逐日记录的 note，供运维解释
	// 「计划移出 N、实际移出 M」的差。真正的删除依据是事务内 swapVerify 的集合校验。
	note := ""
	if cold, err := coldCount(ctx, db, runID, p.Day); err != nil {
		return p, err
	} else if cold != p.Archived {
		note = fmt.Sprintf("预检：口径内未钉住 %d 行，冷块 %d 行，差额 %d 行没有冷副本（超大或 shadow 之后到达），按事务内核对留热",
			p.Archived, cold, p.Archived-cold)
	}
	keep, err := keepSelect(p.Day, run)
	if err != nil {
		return p, err
	}
	verify, err := swapVerify(run, p.Day)
	if err != nil {
		return p, err
	}
	hooks := eventpart.RewriteHooks{
		Verify: verify,
		Record: func(ctx context.Context, tx *sql.Tx, info eventpart.RewriteInfo, kept, dropped int64) error {
			return recordSwapDay(ctx, tx, runID, info.Day, swapDayRecord{
				SwappedAt: time.Now().UTC().Format(time.RFC3339), Kept: kept, Dropped: dropped,
				RunDayVerified: true, Note: note,
			})
		},
		// V09：swap 的派生清理按 guard.go 的逐表决策表收紧——temporal_evaluation_gaps
		// 是有读者的诊断记录，不在 swap 里顺带删；retire 不受影响（走 eventpart 默认清单）。
		DerivedSkip: swapDerivedSkip,
		Observe: func(ctx context.Context, tx *sql.Tx, info eventpart.RewriteInfo, stage string) error {
			if swapTestHook == nil {
				return nil
			}
			return swapTestHook(stage, tx)
		},
	}
	if swapTestHook != nil {
		if err := swapTestHook("prechecks_done", nil); err != nil {
			return p, fmt.Errorf("prechecks_done 阶段注入: %w", err)
		}
	}
	kept, dropped, err := eventpart.RewriteDayGuarded(ctx, db, p.Day, keep, hooks)
	if err != nil {
		if errors.Is(err, eventpart.ErrNothingToRewrite) {
			return p, fmt.Errorf("%s 事务内核对后没有可删事件（口径内的行都被钉住或没有冷副本），无需切换",
				p.Day.Format(time.DateOnly))
		}
		return p, fmt.Errorf("重建日分区 %s: %w", eventpart.DailyName(p.Day), err)
	}
	p.Kept, p.Dropped = kept, dropped
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

// scopePredicate 把 run 的类别与来源写成 SQL 谓词，列名可带限定符（如 "e."），
// 供多表查询（swapVerify 的 CTE）与单表查询（planDay / keepSelect，都把日分区别名为 e）
// 共用同一份字面量，而不是各写一遍后靠注释保证一致。
//
// 值都来自 run 行本身（构建时从 events 里数出来的类别与来源），仍按 SQL 字面量转义：
// 单引号写两遍，类别是整数直接格式化。
func scopePredicate(run Run, qual string) (string, error) {
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
	return fmt.Sprintf(`%[3]sclass_uid = ANY(ARRAY[%[1]s]::bigint[]) AND %[3]ssource = ANY(ARRAY[%[2]s]::text[])`,
		strings.Join(classes, ","), strings.Join(sources, ","), qual), nil
}

// keepSelect 是 RewriteDayGuarded 的保留口径：被钉住的、不属于本 run 类别/来源的、
// 以及**没有被本 run 冷块（event_archive_locator）登记**的行留下，其余移出热表。
// 第三条是 P3 的关键：删除依据不再依赖事务外的计数——shadow 之后到达、或单条超过
// MaxEventBytes 没进冷块的行自动留热，而不是靠「冷块条数 == 待移出条数」的整日门禁兜底。
// locator 行与块同事务写入（writeChunk），所以「在 locator 里」=「有本 run 的冷副本」。
func keepSelect(day time.Time, run Run) (string, error) {
	scope, err := scopePredicate(run, "e.")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`SELECT id FROM %s e WHERE id IN (%s) OR NOT (%s) OR NOT EXISTS (
 SELECT 1 FROM event_archive_locator l
 JOIN event_archive_chunks c ON c.id = l.chunk_id
 WHERE l.event_id = e.id AND c.run_id = '%s' AND c.day = '%s')`,
		eventpart.DailyName(day), eventpart.PinnedIDs, scope, run.ID, day.Format(time.DateOnly)), nil
}

// swapVerify 构造 RewriteDayGuarded 的集合校验闭包（校验内容由本包注入，eventpart 不感知
// 冷归档）。四步全部在重写事务内、SHARE 锁下、删除之前执行，同一条 SQL 取一致快照：
//
//	a) 重算 P：事务内重读 PinnedIDs 中落在该日的集合——SHARE 锁挡得住该日 events 的写入，
//	   挡不住 alerts 等引用表的并发 INSERT，pin 只能在锁内重读才作数；
//	b) 确定 D：该日分区中「属于 run 口径 ∧ 未 pin ∧ 已被本 run 的 locator 登记」的行——
//	   这是唯一允许删除的集合；
//	c) 核对 keep：暂存表（实际保留集）必须恰等于 H − D，差集非空报错并给出首个差异 id；
//	d) 核对覆盖：实际将被删除的行必须全部有冷副本（D ⊆ locator）——由 (b) 的定义理应
//	   成立，这里显式断言一遍，防御口径漂移。
//
// 任何一步失败都让整个重写事务回滚，原分区一行不动。
func swapVerify(run Run, day time.Time) (func(context.Context, *sql.Tx, eventpart.RewriteInfo) error, error) {
	scope, err := scopePredicate(run, "e.")
	if err != nil {
		return nil, err
	}
	// %[1]=日分区 %[2]=口径谓词 %[3]=暂存表 %[4]=PinnedIDs；run_id/day 用绑定参数。
	const query = `WITH pin AS (
 SELECT DISTINCT event_id FROM (%[4]s) pins WHERE pins.event_id IN (SELECT id FROM %[1]s)
), cold AS (
 SELECT l.event_id FROM event_archive_locator l
 JOIN event_archive_chunks c ON c.id = l.chunk_id
 WHERE c.run_id = $1 AND c.day = $2
), d AS (
 SELECT e.id FROM %[1]s e
 WHERE (%[2]s)
   AND NOT EXISTS (SELECT 1 FROM pin WHERE pin.event_id = e.id)
   AND EXISTS (SELECT 1 FROM cold WHERE cold.event_id = e.id)
), expect_keep AS (
 SELECT e.id FROM %[1]s e WHERE NOT EXISTS (SELECT 1 FROM d WHERE d.id = e.id)
)
SELECT v.kind, v.id FROM (
 SELECT 'keep_missing' AS kind, m.id FROM (SELECT id FROM expect_keep EXCEPT SELECT id FROM %[3]s) m
 UNION ALL
 SELECT 'keep_extra' AS kind, x.id FROM (SELECT id FROM %[3]s EXCEPT SELECT id FROM expect_keep) x
 UNION ALL
 SELECT 'uncovered_drop' AS kind, u.id FROM (
   SELECT e.id FROM %[1]s e WHERE NOT EXISTS (SELECT 1 FROM %[3]s s WHERE s.id = e.id)
   EXCEPT SELECT event_id FROM cold) u
) v ORDER BY v.kind, v.id LIMIT 6`
	return func(ctx context.Context, tx *sql.Tx, info eventpart.RewriteInfo) error {
		rows, err := tx.QueryContext(ctx, fmt.Sprintf(query, info.Daily, scope, info.Staging, eventpart.PinnedIDs),
			run.ID, info.Day)
		if err != nil {
			return fmt.Errorf("事务内核对删除依据: %w", err)
		}
		defer rows.Close()
		var violations []string
		for rows.Next() {
			var kind string
			var id uuid.UUID
			if err := rows.Scan(&kind, &id); err != nil {
				return fmt.Errorf("读取核对结果: %w", err)
			}
			violations = append(violations, kind+" "+id.String())
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("核对删除依据: %w", err)
		}
		if len(violations) > 0 {
			return fmt.Errorf("切换校验失败，事务回滚、原分区未动：%s（keep_missing=应保留未保留，"+
				"keep_extra=应删未删，uncovered_drop=要删的行没有冷副本）", strings.Join(violations, "、"))
		}
		return nil
	}, nil
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

// swapDayRecord 是写进 run 的 detail.days.<UTC 日> 的那段 JSON：一天的实际切换结果。
// P3 起取代单个 detail.swapped 值——一个 run 常跨多天，单值会把前一天的记录覆盖掉；
// jsonb_set 定位到 {days,<day>} 单键，多日互不覆盖。
type swapDayRecord struct {
	SwappedAt      string `json:"swapped_at"`
	Kept           int64  `json:"kept"`
	Dropped        int64  `json:"dropped"`
	RunDayVerified bool   `json:"run_day_verified"`
	Note           string `json:"note,omitempty"`
}

// recordSwapDay 把某日的切换结果合并进 run 的 detail（键 days.<day>），不改 status。
// 只由 RewriteDayGuarded 的 Record 注入点调用：与分区替换同一个事务，
// 提交结果要么「分区已换 + 记录已写」，要么两者都没发生。
//
// jsonb_set 的 create_missing 只补最末一级路径，中间键不存在时静默不生效，所以不能直接
// 定位到 {days,<day>}；这里以单键 {days} 为目标，把该日记录（键即 UTC 日）合并进已有的
// days 对象——同 run 多日互不覆盖，重复切换同一日则覆盖该日自己的记录。
func recordSwapDay(ctx context.Context, tx *sql.Tx, runID uuid.UUID, day time.Time, rec swapDayRecord) error {
	encoded, err := json.Marshal(map[string]swapDayRecord{day.Format(time.DateOnly): rec})
	if err != nil {
		return fmt.Errorf("序列化 run %s 的 detail.days.%s: %w", runID, day.Format(time.DateOnly), err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE event_archive_runs
 SET detail = jsonb_set(COALESCE(detail, '{}'::jsonb), '{days}',
  COALESCE(detail->'days', '{}'::jsonb) || $2::jsonb, true)
 WHERE id = $1`, runID, encoded); err != nil {
		return fmt.Errorf("run %s 写 detail.days.%s 失败，分区替换将连同本事务一起回滚: %w",
			runID, day.Format(time.DateOnly), err)
	}
	return nil
}
