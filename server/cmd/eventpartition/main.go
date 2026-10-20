// eventpartition 把老库的普通 events 表在线迁移成按天分区的表。分步执行，每步单独确认：
//
//	check → prepare → copy → index → verify [→ repair → verify] → switch → （观察）→ finish
//	                                                                 └→ rollback
//	切换前任何时候可 abort 放弃。
//
// check 与 verify 只读；其余步骤会改库，必须加 -confirm，否则拒绝执行（没有演练模式）。
// copy / index 可以随时中断（Ctrl-C），重跑同一步从断点续上。设计与生产步骤见 docs/event-partitioning.md。
//
// 用法: DATABASE_URL=... eventpartition [-pgdata /var/lib/postgresql/data] [-confirm] <步骤>
//
// -pgdata 指向数据库数据目录（在数据库主机或容器里运行），用来核对磁盘余量：迁移期间新旧两份数据并存，
// 余量不足拒绝 prepare / copy / index。主备两台都要有余量，备库上可以跑只读的 check 核对。
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/internal/eventpart"
)

func main() {
	pgdata := flag.String("pgdata", "", "数据库数据目录，用于检查磁盘余量")
	confirm := flag.Bool("confirm", false, "确认执行会改动数据库的步骤")
	retention := flag.Int("retention-days", 30, "与 server 的 RETENTION_DAYS 一致：更早的事件建成月归档分区（prepare 用）")
	chunk := flag.Duration("chunk", time.Hour, "copy 每批覆盖的事件时间跨度")
	pause := flag.Duration("pause", 0, "copy 每批之间的停顿，给线上读写让出 IO")
	lockTimeout := flag.Duration("lock-timeout", 5*time.Second, "prepare / switch / rollback / finish 等锁的上限，超时整步放弃")
	day := flag.String("day", "", "repair 只修这一天（YYYY-MM-DD，UTC），缺省修全部不一致的日子")
	flag.Parse()
	dsn := os.Getenv("DATABASE_URL")
	if flag.NArg() != 1 || dsn == "" {
		fmt.Fprintln(os.Stderr, "用法: DATABASE_URL=... eventpartition [-pgdata 目录] [-confirm] check|prepare|copy|index|verify|repair|switch|rollback|finish|abort")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer db.Close()
	m := &eventpart.Migrator{DB: db, Out: os.Stdout, RetentionDays: *retention, Chunk: *chunk, Pause: *pause, LockTimeout: *lockTimeout}
	if *pgdata != "" {
		m.Free = func() (uint64, error) { return freeBytes(*pgdata) }
	}
	if err := m.Run(ctx, flag.Arg(0), *confirm, *day); err != nil {
		fmt.Fprintln(os.Stderr, "失败:", err)
		os.Exit(1)
	}
}

// freeBytes 是目录所在文件系统对非特权用户可用的剩余字节。
func freeBytes(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, fmt.Errorf("读取 %s 的磁盘余量: %w", dir, err)
	}
	return st.Bavail * uint64(st.Bsize), nil
}
