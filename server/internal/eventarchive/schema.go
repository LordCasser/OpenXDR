package eventarchive

import (
	"context"
	"database/sql"
	"fmt"
)

// 运行状态。影子构建结束仍是 building（等对拍），对拍通过才 verified；
// 构建或对拍出错记 failed，error 列写原因。
const (
	StatusBuilding = "building"
	StatusVerified = "verified"
	StatusFailed   = "failed"
)

// schemaDDL 只建两张新表。两张表都不引用 events（冷归档与 events 没有任何外键或触发器关系）：
// 阶段 A 只读 events，写这两张表；events 的行、索引与分区一概不碰。
//
// id_bloom 是阶段 B2 加的**可空**列（按 ID 定位用的 Bloom filter）；老库靠后面那条
// ADD COLUMN IF NOT EXISTS 幂等补上，老行留 NULL 表示「没有过滤器，按 ID 查时必须解压」。
// 已有列、已有约束一概不动，也不加 NOT NULL。
const schemaDDL = `CREATE TABLE IF NOT EXISTS event_archive_chunks (
 id uuid PRIMARY KEY,
 run_id uuid NOT NULL,
 seq int NOT NULL,
 day date NOT NULL,
 class_uid int NOT NULL,
 source text NOT NULL,
 first_ts timestamptz NOT NULL,
 last_ts timestamptz NOT NULL,
 event_count int NOT NULL,
 format smallint NOT NULL,
 codec smallint NOT NULL,
 plain_len bigint NOT NULL,
 payload_len bigint NOT NULL,
 plain_sha256 bytea NOT NULL,
 payload bytea NOT NULL,
 id_bloom bytea,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE (run_id, seq));
ALTER TABLE event_archive_chunks ADD COLUMN IF NOT EXISTS id_bloom bytea;
CREATE INDEX IF NOT EXISTS event_archive_chunks_day ON event_archive_chunks (day, class_uid, source);
CREATE INDEX IF NOT EXISTS event_archive_chunks_ts ON event_archive_chunks (first_ts, last_ts);
CREATE TABLE IF NOT EXISTS event_archive_runs (
 id uuid PRIMARY KEY,
 started_at timestamptz,
 finished_at timestamptz,
 status text NOT NULL,
 day_from date NOT NULL,
 day_to date NOT NULL,
 classes int[] NOT NULL,
 sources text[] NOT NULL,
 scanned bigint NOT NULL DEFAULT 0,
 archived bigint NOT NULL DEFAULT 0,
 pinned_skipped bigint NOT NULL DEFAULT 0,
 chunks int NOT NULL DEFAULT 0,
 error text,
 detail jsonb)`

// EnsureSchema 建冷归档的两张表与索引，幂等，可重复执行；老库上补加 `id_bloom` 列
// （`ADD COLUMN IF NOT EXISTS`，只加可空列，不改已有列、不加约束）。
// 不改 events、不加指向 events 的外键；payload 允许 TOAST，不给大字段建索引。
func EnsureSchema(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, schemaDDL); err != nil {
		return fmt.Errorf("建冷归档表: %w", err)
	}
	return nil
}
