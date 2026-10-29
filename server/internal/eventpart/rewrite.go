package eventpart

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// rewriteSuffix 是暂存表的后缀：日分区 events_pYYYYMMDD 重建时先写成
// events_pYYYYMMDD_rewrite，核对完再改名接上父表。
const rewriteSuffix = "_rewrite"

// RewriteDay 把一个日分区重建成只保留 keepSelect 选出的行，返回保留数与删除数。
//
// keepSelect 必须是「SELECT id FROM ...」形式的**只读**查询，由调用方给出保留口径
// （冷归档用它表达「被钉住的 + 不属于本 run 口径的」）。选中的行留在日分区里，
// 其余行随旧分区一起消失——这是全项目唯一会丢数据的分区操作，所以每一步都照 retireDay 的口径：
//
//  1. 只认独立日分区：该日的行还在默认分区（events_default）时直接报错，要求先 EnsureDays，
//     绝不自己去默认分区搬行；
//  2. 事务里先对日分区加 SHARE 锁：读照常，写入该日的迟到事件等待，复制期间行集不再变化；
//  3. 建暂存表 (LIKE parent INCLUDING DEFAULTS) → INSERT 保留行 → cloneIndexes
//     （与 retire 共用同一份索引克隆，ATTACH 时直接挂上，不在排他锁里现建索引）；
//  4. 独立数一遍 keepSelect 的行数，与暂存表实际行数不符即中止：keepSelect 指到别的表、
//     别的日分区或已被搬走的行时，这里会立刻露出来。删掉的若是整分区，那是事故不是本意；
//  5. 派生状态按 retire 的同一份清单清理（删分区不触发逐行级联触发器，必须显式做）；
//  6. DETACH → DROP → RENAME → ATTACH 全在同一事务里：PostgreSQL 的 DDL 是事务性的，
//     任何一步失败都整体回滚，原分区及其索引、触发器原样保留。
//
// 不用 TRUNCATE，也不 DELETE FROM events：逐行删除会触发证据保护与级联触发器，
// 代价和语义都不是这里要的。失败一律返回错误，不吞。
func RewriteDay(ctx context.Context, db *sql.DB, day time.Time, keepSelect string) (kept, dropped int64, err error) {
	keep, err := checkKeepSelect(ctx, db, keepSelect)
	if err != nil {
		return 0, 0, err
	}
	d := dayStart(day)
	daily := DailyName(d)
	set, err := listPartitions(ctx, db, Parent)
	if err != nil {
		return 0, 0, err
	}
	if !set.byName[daily] {
		return 0, 0, fmt.Errorf("%s 没有独立日分区 %s：该日的行在默认分区里，"+
			"先跑 EnsureDays 建好日分区再重写（本函数不碰默认分区）", d.Format(time.DateOnly), daily)
	}
	staging := daily + rewriteSuffix
	lo, hi := literal(d), literal(d.AddDate(0, 0, 1))

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	exec := func(stmt string) (sql.Result, error) { return tx.ExecContext(ctx, stmt) }
	for _, stmt := range []string{
		`SET LOCAL lock_timeout = '` + LockTimeout + `'`,
		fmt.Sprintf(`LOCK TABLE %s IN SHARE MODE`, daily),
		fmt.Sprintf(`CREATE TABLE %s (LIKE %s INCLUDING DEFAULTS)`, staging, Parent),
	} {
		if _, err := exec(stmt); err != nil {
			return 0, 0, err
		}
	}
	var total int64
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM `+daily).Scan(&total); err != nil {
		return 0, 0, fmt.Errorf("统计 %s 行数: %w", daily, err)
	}
	// 保留集自己数一遍，再与实际写进暂存表的行数比：两者不符说明 keepSelect 与这个日分区
	// 不是同一批行，此刻中止还能保住原分区
	var selected int64
	if err := tx.QueryRowContext(ctx, fmt.Sprintf(`SELECT count(DISTINCT id) FROM (%s) AS keep_ids`, keep)).
		Scan(&selected); err != nil {
		return 0, 0, fmt.Errorf("执行保留口径: %w", err)
	}
	if _, err := exec(fmt.Sprintf(`INSERT INTO %s (%s) SELECT %s FROM %s WHERE id IN (%s)`,
		staging, Columns, Columns, daily, keep)); err != nil {
		return 0, 0, err
	}
	var keptRows int64
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM `+staging).Scan(&keptRows); err != nil {
		return 0, 0, fmt.Errorf("统计暂存表 %s 行数: %w", staging, err)
	}
	if keptRows != selected {
		return 0, 0, fmt.Errorf("保留计数不符：keepSelect 选出 %d 条，%s 里只有 %d 条（共 %d 条），"+
			"中止，原分区未改动", selected, daily, keptRows, total)
	}
	if keptRows > total {
		return 0, 0, fmt.Errorf("保留 %d 条超过 %s 的 %d 条，中止，原分区未改动", keptRows, daily, total)
	}
	for _, dv := range derived {
		stmt := fmt.Sprintf(`DELETE FROM %s WHERE %s IN (SELECT id FROM %s EXCEPT SELECT id FROM %s)`,
			dv.table, dv.column, daily, staging)
		if _, err := exec(stmt); err != nil {
			return 0, 0, fmt.Errorf("清理派生状态 %s: %w", dv.table, err)
		}
	}
	if err := cloneIndexes(ctx, tx, Parent, staging); err != nil {
		return 0, 0, err
	}
	for _, stmt := range []string{
		fmt.Sprintf(`ALTER TABLE %s DETACH PARTITION %s`, Parent, daily),
		`DROP TABLE ` + daily,
		fmt.Sprintf(`ALTER TABLE %s RENAME TO %s`, staging, daily),
		fmt.Sprintf(`ALTER TABLE %s ATTACH PARTITION %s FOR VALUES FROM (%s) TO (%s)`, Parent, daily, lo, hi),
	} {
		if _, err := exec(stmt); err != nil {
			return 0, 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		// 提交失败即整体回滚：原分区完好，计数不能当成已生效
		return 0, 0, err
	}
	return keptRows, total - keptRows, nil
}

// checkKeepSelect 校验 keepSelect 是单条只读查询并返回去掉首尾空白后的语句。
//
// 前缀与分号只是第一道闸门（挡住拼进第二条语句）；只读性由只读事务里的试执行兜底：
// 任何写数据的语句在 READ ONLY 事务里都会被 PostgreSQL 拒绝，包括
// `WITH x AS (INSERT ... RETURNING id) SELECT id FROM x` 这种形如 SELECT 的写法。
// 用 LIMIT 1 只取一行，验证的是「能不能执行」而不是结果有多少。
func checkKeepSelect(ctx context.Context, db *sql.DB, keepSelect string) (string, error) {
	keep := strings.TrimSpace(keepSelect)
	if keep == "" {
		return "", errors.New("keepSelect 不能为空")
	}
	if !startsWithKeyword(keep, "select") {
		return "", fmt.Errorf("keepSelect 必须是以 SELECT 开头的只读查询，实际是 %q", firstLine(keep))
	}
	if strings.Contains(keep, ";") {
		return "", errors.New("keepSelect 只能是一条语句（不允许分号）")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`SELECT id FROM (%s) AS keep_ids LIMIT 1`, keep))
	if err != nil {
		return "", fmt.Errorf("keepSelect 不可执行或不是只读查询: %w", err)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("keepSelect 不可执行或不是只读查询: %w", err)
	}
	return keep, nil
}

// startsWithKeyword 报告 s 是否以关键字 keyword 开头（大小写不敏感，后面必须跟空白）。
func startsWithKeyword(s, keyword string) bool {
	if len(s) < len(keyword) || !strings.EqualFold(s[:len(keyword)], keyword) {
		return false
	}
	return len(s) == len(keyword) || s[len(keyword)] == ' ' || s[len(keyword)] == '\n' ||
		s[len(keyword)] == '\t' || s[len(keyword)] == '\r'
}

// firstLine 截出错信息里要展示的部分：keepSelect 可能很长，报错只带第一行前 80 字节。
func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	const max = 80
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
