// eventarchive 是冷归档的阶段 A（影子归档）的命令行：只写新建的 event_archive_chunks /
// event_archive_runs 两张表，**不改动 events 的任何一行**，也不 DETACH / ATTACH / DROP 分区。
//
// 用法: DATABASE_URL=... eventarchive <子命令>
//
//	ensure-schema                                    建两张新表（幂等）
//	shadow -from 2026-09-01 -to 2026-09-14 [-classes 4001,4003] [-sources agent,sensor]
//	       [-chunk-events 2048] [-chunk-bytes 1048576] -confirm
//	verify -run <uuid>                               按 run 口径重扫对拍，通过才置 verified
//	report -run <uuid>                               归档前后的真实大小与压缩比
//	locate -id <uuid>                                按事件 ID 找一条冷事件（只读）
//	materialize -id <uuid> -confirm                  把一条冷事件物化回 events（幂等，不产告警）
//
// shadow / materialize 会写库，不加 -confirm 直接拒绝（没有演练模式）。verify 只改 run 的
// 状态列；locate 只读。设计与阶段见 docs/event-archive.md；分区侧的工程口径见
// docs/event-partitioning.md。
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/internal/eventarchive"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "缺少 DATABASE_URL")
		usage()
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer db.Close()
	if err := run(ctx, db, os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "失败:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `用法: DATABASE_URL=... eventarchive <子命令>
  ensure-schema                                     建 event_archive_chunks / event_archive_runs（幂等）
  shadow -from YYYY-MM-DD -to YYYY-MM-DD [选项] -confirm
                                                    影子归档：只读 events，写冷块（会写库）
       -classes 4001,4003     归档类别（默认 4001,4003）
       -sources agent,sensor  来源（默认范围内全部）
       -chunk-events 2048     单块事件条数上限
       -chunk-bytes 1048576   单块未压缩明文字节上限
  verify -run <uuid>                                重扫对拍，通过后置 verified
  report -run <uuid>                                归档前后大小、压缩比与含索引对比
  locate -id <uuid>                                 按事件 ID 找一条冷事件（只读）
  materialize -id <uuid> -confirm                   把一条冷事件物化回 events（幂等，不产告警）`)
	os.Exit(2)
}

func run(ctx context.Context, db *sql.DB, cmd string, args []string) error {
	switch cmd {
	case "ensure-schema":
		fs := flag.NewFlagSet("ensure-schema", flag.ExitOnError)
		fs.Parse(args)
		if err := eventarchive.EnsureSchema(ctx, db); err != nil {
			return err
		}
		fmt.Println("已确保冷归档表存在：event_archive_chunks、event_archive_runs")
		return nil

	case "shadow":
		fs := flag.NewFlagSet("shadow", flag.ExitOnError)
		from := fs.String("from", "", "起始日（YYYY-MM-DD，UTC，含）")
		to := fs.String("to", "", "结束日（YYYY-MM-DD，UTC，含）")
		classes := fs.String("classes", "4001,4003", "归档类别，逗号分隔")
		sources := fs.String("sources", "", "来源，逗号分隔；空为范围内全部")
		chunkEvents := fs.Int("chunk-events", eventarchive.DefaultChunkEvents, "单块事件条数上限")
		chunkBytes := fs.Int("chunk-bytes", eventarchive.DefaultChunkBytes, "单块未压缩明文字节上限")
		confirm := fs.Bool("confirm", false, "确认执行会写库的步骤")
		fs.Parse(args)
		dayFrom, err := parseDay(*from)
		if err != nil {
			return fmt.Errorf("-from: %w", err)
		}
		dayTo, err := parseDay(*to)
		if err != nil {
			return fmt.Errorf("-to: %w", err)
		}
		classList, err := parseClasses(*classes)
		if err != nil {
			return err
		}
		runID, err := eventarchive.Shadow(ctx, db, eventarchive.Options{
			From: dayFrom, To: dayTo, Classes: classList, Sources: parseList(*sources),
			ChunkEvents: *chunkEvents, ChunkBytes: *chunkBytes, Confirm: *confirm,
		})
		if err != nil {
			return err
		}
		runInfo, err := eventarchive.LoadRun(ctx, db, runID)
		if err != nil {
			return err
		}
		fmt.Printf("影子归档 run %s 完成（status=%s）\n", runID, runInfo.Status)
		fmt.Printf("  候选 %d 条：归档 %d 条（%d 块），被钉住跳过 %d 条\n",
			runInfo.Scanned, runInfo.Archived, runInfo.Chunks, runInfo.PinnedSkip)
		fmt.Printf("  口径 %s..%s（UTC），类别 %v，来源 %v\n",
			runInfo.DayFrom.Format(time.DateOnly), runInfo.DayTo.Format(time.DateOnly), runInfo.Classes, runInfo.Sources)
		fmt.Println("  下一步：eventarchive verify -run", runID)
		return nil

	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		id := fs.String("run", "", "要核对的 run id（uuid）")
		fs.Parse(args)
		runID, err := parseRun(*id)
		if err != nil {
			return err
		}
		if err := eventarchive.Verify(ctx, db, runID); err != nil {
			return err
		}
		fmt.Printf("run %s 对拍通过：逐事件全字段一致，已置 verified\n", runID)
		return nil

	case "report":
		fs := flag.NewFlagSet("report", flag.ExitOnError)
		id := fs.String("run", "", "要度量的 run id（uuid）")
		fs.Parse(args)
		runID, err := parseRun(*id)
		if err != nil {
			return err
		}
		r, err := eventarchive.Measure(ctx, db, runID)
		if err != nil {
			return err
		}
		fmt.Print(r.String())
		return nil

	case "locate":
		fs := flag.NewFlagSet("locate", flag.ExitOnError)
		id := fs.String("id", "", "要定位的事件 id（uuid）")
		fs.Parse(args)
		eventID, err := parseID(*id)
		if err != nil {
			return err
		}
		e, found, err := eventarchive.Locate(ctx, db, eventID)
		if err != nil {
			return err
		}
		if !found {
			fmt.Printf("冷层命中：否（候选块全部解压比对过，冷层确实没有这条事件）\n")
			fmt.Printf("  id = %s\n", eventID)
			return nil
		}
		fmt.Printf("冷层命中：是（在冷块中找到）\n")
		fmt.Printf("  id        = %s\n", e.ID)
		fmt.Printf("  ts        = %s\n", e.Ts.Format(time.RFC3339Nano))
		fmt.Printf("  class_uid = %d\n", e.ClassUID)
		fmt.Printf("  source    = %s\n", e.Source)
		fmt.Printf("  asset_id  = %s\n", optionalUUID(e.AssetID))
		return nil

	case "materialize":
		fs := flag.NewFlagSet("materialize", flag.ExitOnError)
		id := fs.String("id", "", "要物化的事件 id（uuid）")
		confirm := fs.Bool("confirm", false, "确认执行会写库的步骤")
		fs.Parse(args)
		eventID, err := parseID(*id)
		if err != nil {
			return err
		}
		if !*confirm {
			return fmt.Errorf("物化会往 events 插入一行，必须显式确认（-confirm）")
		}
		inserted, err := eventarchive.Materialize(ctx, db, eventID)
		if err != nil {
			return err
		}
		if inserted {
			fmt.Printf("已物化事件 %s：往 events 插入 1 行（复制，不经过检测器，不产告警）\n", eventID)
			return nil
		}
		// inserted=false 有两种原因，用 Locate 分清：events 里本来就有（幂等），还是冷层没有。
		_, found, locateErr := eventarchive.Locate(ctx, db, eventID)
		switch {
		case locateErr != nil:
			fmt.Printf("未插入（inserted=false）：events 里已有这条事件，或冷层没有；复查冷层失败: %v\n", locateErr)
		case !found:
			fmt.Printf("冷层没有事件 %s：未插入任何行\n", eventID)
		default:
			fmt.Printf("事件 %s 已在 events 里：未插入（物化幂等，events 里只有这一行）\n", eventID)
		}
		return nil
	}
	usage()
	return nil
}

func parseDay(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("必填（YYYY-MM-DD）")
	}
	return time.Parse(time.DateOnly, s)
}

func parseRun(s string) (uuid.UUID, error) {
	if s == "" {
		return uuid.Nil, fmt.Errorf("-run 必填（uuid）")
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, fmt.Errorf("-run %q 不是 uuid: %w", s, err)
	}
	return id, nil
}

func parseID(s string) (uuid.UUID, error) {
	if s == "" {
		return uuid.Nil, fmt.Errorf("-id 必填（uuid）")
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, fmt.Errorf("-id %q 不是 uuid: %w", s, err)
	}
	return id, nil
}

func optionalUUID(id *uuid.UUID) string {
	if id == nil {
		return "NULL"
	}
	return id.String()
}

func parseList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseClasses(s string) ([]int, error) {
	var out []int
	for _, part := range parseList(s) {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("-classes 里的 %q 不是整数: %w", part, err)
		}
		out = append(out, n)
	}
	return out, nil
}
