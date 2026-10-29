package eventarchive

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// 阶段 B2：按事件 ID 定位冷事件（定位、存在性判断、证据物化）。
//
// 冷块元数据里没有 ID 索引，逐块解压全文扫在生产上不可接受，所以每块带一个 ID Bloom
// filter（chunk.go 的 BuildIDBloom / MayContainID）。filter 只负责**排除不可能命中的块**，
// 通过 filter 的块仍要解压并逐事件精确比对 ID：假阳性只是多解压几块，漏报才是事故
// （重传被当成新事件 → 重复告警；证据物化找不到事件）。
//
// 本文件与阶段 A/B1 的关系：
//   - 只读 event_archive_chunks（`Materialize` 额外往 events 插入缺失的行，不删不改）；
//   - 不产告警、不动派生表：证据物化是复制，不是重放。
//
// 重传判重（阶段 C 已接线，见 docs/event-archive.md 第 9 节）的调用方是接入路径：
// 它只经 main.go 的适配器调用 Exists 与 Boundary，且只在「事件时间不晚于归档边界」时
// 发按 ID 查询；本包不知道自己被谁调用。

// ErrChunkBudget 表示「通过 Bloom filter 的候选块超过预算，已扫的块里没有这条事件，
// 但**不能**断言冷层没有它」。所有「找不到」的结论都必须落在「全部候选块都解压比对过」
// 之上；预算用完还继续扫会把延迟与内存交给归档规模，因此这里如实报错，由调用方决定
// 是缩小范围还是调高预算。
var ErrChunkBudget = errors.New("候选块超出预算，无法确认不存在")

// Locate 按事件 ID 找一条冷事件。found=false 且 err=nil 表示冷层确实没有这条事件。
// 冷层不可用（没有表）返回 ErrNoSchema；块损坏返回错误（带块 id），不得当作「没有这条事件」。
//
// 候选块按 (first_ts, last_ts, id) 倒序（新块优先）取；每块的 id_bloom 为 NULL 时一律
// 进入候选（阶段 B2 之前写的老块没有过滤器），非 NULL 时用 MayContainID 先排掉。
// 通过 filter 的块解压后逐事件精确比对 ID，命中即返回。
//
// 判定的强度分三档，调用方必须分清：
//   - found=true：确定存在，返回的就是冷块里的那条事件；
//   - found=false + err=nil：全部候选块都解压比对过，确定冷层没有；
//   - err=ErrChunkBudget：候选块超出预算（maxScannedChunks），**无法确认**不存在。
//
// 与 Query 一样，块损坏整体报错、不跳过：跳过坏块等于把「查不到」伪装成「不存在」。
func Locate(ctx context.Context, db *sql.DB, id uuid.UUID) (Event, bool, error) {
	if db == nil {
		return Event{}, false, errors.New("冷归档定位需要数据库连接")
	}
	cands, over, err := locateCandidates(ctx, db, id)
	if err != nil {
		return Event{}, false, err
	}
	src := &sqlSource{db: db}
	for _, cand := range cands {
		ch, err := src.load(ctx, cand.ID)
		if err != nil {
			return Event{}, false, err
		}
		events, err := ch.Block.Decode()
		if err != nil {
			return Event{}, false, fmt.Errorf("解码冷块 %s（seq %d，%s/%s）: %w",
				ch.ID, ch.Seq, ch.Day.Format(time.DateOnly), ch.Source, err)
		}
		// 块自洽同样要核：列与内容不符说明归档被改过，此时「解出来没有」不足以支撑「不存在」。
		if err := ch.check(events); err != nil {
			return Event{}, false, fmt.Errorf("冷块 %s（seq %d）内容与头部不符: %w", ch.ID, ch.Seq, err)
		}
		for _, e := range events {
			if e.ID == id {
				return e, true, nil
			}
		}
	}
	if over {
		return Event{}, false, fmt.Errorf("%w：按 ID %s 过滤后仍有超过 %d 块可能需要解压，"+
			"已解压的块里都没有这条事件", ErrChunkBudget, id, maxScannedChunks)
	}
	return Event{}, false, nil
}

// Exists 是 Locate 的便捷包装：存在返回 true。错误语义同 Locate——块损坏、冷层不可用
// 与 ErrChunkBudget 都是错误，只有「确实没有」才返回 (false, nil)。
//
// 重传判重（阶段 C 已接线）只接受这种口径：拿 false 就必须能确定冷层没有，
// 拿不准时报错比静默当成新事件安全。
func Exists(ctx context.Context, db *sql.DB, id uuid.UUID) (bool, error) {
	_, found, err := Locate(ctx, db, id)
	return found, err
}

// Boundary 返回冷层最晚的事件时间（max(last_ts)）以及归档是否非空。它是接入侧
// 「时间闸门」的唯一依据：事件时间晚于这个边界就不可能在冷块里，连 Exists 都不用发
// （接入峰值约 3000 条/秒，逐条查块元数据不可接受）。
//
// 只读一条聚合，不解压、不读 id_bloom，也不缓存：边界该由调用方按自己的节奏缓存
// （ingest 侧 60 秒），这里保持无状态、与 Locate / Query 一样只报告当下的事实。
// 冷层没有表时返回 ErrNoSchema（部署状态，不是数据错误）；ok=false 只表示还没有任何块。
func Boundary(ctx context.Context, db *sql.DB) (last time.Time, ok bool, err error) {
	if db == nil {
		return time.Time{}, false, errors.New("冷归档边界查询需要数据库连接")
	}
	var latest sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT max(last_ts) FROM event_archive_chunks`).Scan(&latest); err != nil {
		return time.Time{}, false, wrapErr(err, "查询冷归档边界")
	}
	if !latest.Valid {
		return time.Time{}, false, nil
	}
	return latest.Time.UTC(), true, nil
}

// Materialize 把一条冷事件物化回 events 普通行，供「冷事件重新成为证据」时使用。
// 返回 inserted=false 表示 events 里本来就有（幂等）。
// 不经过检测器：不产规则命中、不产告警、不改任何派生表。
//
// 冷层找不到这条事件时返回 (false, nil)，**不插入任何行**；此时它与「events 里本来就有」
// 的返回值相同，要区分两者用 Locate / Exists 另查一次（插入后 events 里必有该行，
// 冷层有则 Locate 仍能命中）。
//
// 冷块保持不可变：物化是复制，不回写、不删块、不改 run。插入是单事务里的一条
// `INSERT ... ON CONFLICT DO NOTHING`，并发重复物化最多插一行，不会产生第二行，
// 也不会覆盖 events 里已有的行。events 的 foreign key（asset_id → assets）与分区路由
// 仍由数据库判定：目标资产已不存在时报错，不静默丢字段。
func Materialize(ctx context.Context, db *sql.DB, id uuid.UUID) (inserted bool, err error) {
	e, found, err := Locate(ctx, db, id)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("物化事件 %s: %w", id, err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `INSERT INTO events
 (id, ts, class_uid, source, asset_id, process_guid, parent_process_guid, username, conn_tuple, raw)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING`,
		e.ID, e.Ts, e.ClassUID, e.Source, nullableUUID(e.AssetID), nullableUUID(e.ProcessGUID),
		nullableUUID(e.ParentProcessGUID), nullableString(e.Username), nullableString(e.ConnTuple), e.Raw)
	if err != nil {
		return false, fmt.Errorf("物化事件 %s: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("物化事件 %s: %w", id, err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("物化事件 %s: %w", id, err)
	}
	return n > 0, nil
}

// locateCandidate 是候选块的元数据加 ID Bloom filter（不含载荷）。
type locateCandidate struct {
	chunkMeta
	bloom []byte
}

// locateCandidates 只取块元数据，用 filter 排掉不可能命中的块，按 (first_ts, last_ts, id)
// 倒序返回最多 maxScannedChunks 个候选。over 为真表示还有通过 filter 的块没返回：
// 那就是 ErrChunkBudget 的情形。
//
// 只扫元数据、不解压：内存是「最多 maxScannedChunks 份 filter」，每块至多
// MaxCount*BloomBits/8 字节（8192 条 ≈ 10 KiB）。
func locateCandidates(ctx context.Context, db *sql.DB, id uuid.UUID) (cands []locateCandidate, over bool, err error) {
	rows, err := db.QueryContext(ctx, `SELECT id, seq, day, class_uid, source, first_ts, last_ts, event_count, id_bloom
 FROM event_archive_chunks ORDER BY first_ts DESC, last_ts DESC, id`)
	if err != nil {
		return nil, false, wrapErr(err, "列出冷块候选")
	}
	defer rows.Close()
	for rows.Next() {
		var c locateCandidate
		if err := rows.Scan(&c.ID, &c.Seq, &c.Day, &c.ClassUID, &c.Source, &c.FirstTs, &c.LastTs,
			&c.Count, &c.bloom); err != nil {
			return nil, false, wrapErr(err, "读取冷块元数据")
		}
		c.Day, c.FirstTs, c.LastTs = c.Day.UTC(), c.FirstTs.UTC(), c.LastTs.UTC()
		if !MayContainID(c.bloom, id) {
			continue // filter 说不可能：连解压都不做，这正是 Bloom 存在的意义
		}
		if len(cands) == maxScannedChunks {
			over = true
			break
		}
		cands = append(cands, c)
	}
	if err := rows.Err(); err != nil {
		return nil, false, wrapErr(err, "列出冷块候选")
	}
	return cands, over, nil
}

// nullableUUID / nullableString 把可空列原样交给 database/sql：nil 就是 SQL NULL，
// 不把 NULL 折成零值。
func nullableUUID(id *uuid.UUID) any {
	if id == nil {
		return nil
	}
	return *id
}

func nullableString(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}
