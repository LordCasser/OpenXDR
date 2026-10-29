# 冷归档

events 保留期内的数据在日分区里，过期分区由 `eventpart.Retire` 整体退役（见
`docs/event-partitioning.md`）。退役之外还有一类需求：**把过期但仍有价值的事件压成冷块长期保留**，
查询时按需解压。本文是冷归档的格式、口径与阶段划分；目前实现的是**阶段 A：影子归档**。

代码：`server/internal/eventarchive`（冷块编解码、影子构建、对拍、度量），
`server/cmd/eventarchive`（命令行）。

## 1. 阶段划分

| 阶段 | 做什么 | 状态 |
|---|---|---|
| **A 影子归档** | 只读 events，把候选事件编码成冷块写进两张新表，逐事件对拍 + 度量 | **已实现** |
| B 冷热查询 | 热数据仍查 events，冷块按 (day, class_uid, source) 定位后解压回放 | 未实现 |
| C 切换与释放 | 冷块验证覆盖足够后，才谈退役分区、删行、真正释放空间 | 未实现 |

阶段 A 的铁律：**不改动、删除或切换 events 的任何一行**。不改 `events` 与其索引，
不 `DETACH` / `ATTACH` / `DROP` 任何分区，不调用 `eventpart.Retire`，不给 events 加外键或触发器。
写入只发生在两张新建表上：`event_archive_chunks`、`event_archive_runs`。
正因为如此，阶段 A 无论跑多少轮都不影响线上读写路径，也不需要停写窗口或额外磁盘余量规划
（冷块本身要占空间，约等于归档范围的明文压缩后大小）。

## 2. 冷块格式

一块冷块 = 头部 + 载荷。头部在库里是 `event_archive_chunks` 的列；导出或单独存档时用
`Block.MarshalBinary` 拼回下面这套字节布局，读端 `DecodeBlock` 可独立解码：

```
magic(8) "OXDRARC1" | format(1) | codec(1) | count(4, BE) | plainLen(8, BE) | plainSHA256(32) | payload
```

| 字段 | 含义 |
|---|---|
| `magic` | 固定 `OXDRARC1`，用来把冷块与任意字节流区分开 |
| `format` | 格式版本，当前只有 `1`（`FormatV1`）；不能识别的版本直接拒绝 |
| `codec` | `0` = 原文；`1` = zstd（`klauspost/compress/zstd`，`EncodeAll`、并发 1、级别 1） |
| `count` | 块内事件条数 |
| `plainLen` | 解压后明文字节数 |
| `plainSHA256` | 明文的 SHA-256，用来发现载荷损坏 |
| `payload` | zstd frame，或未压缩的明文 |

**载荷**是逐行 JSON：`\n` 分隔，末行不带 `\n`；每行是一条事件，字段顺序由 `Event` 的声明顺序固定，
因此同样的输入两次编码字节完全一致。字段与 events 的公共列一一对应：

```json
{"id":"…","ts":"2026-09-01T00:00:00Z","class_uid":4001,"source":"agent",
 "asset_id":null,"process_guid":null,"parent_process_guid":null,
 "username":"root","conn_tuple":"10.0.0.1:50000>10.0.0.2:443","raw":{"…":"…"}}
```

- `ts` 用 RFC3339Nano、UTC；`raw` 用 `json.RawMessage`，**原样写入** events 里 jsonb 的文本表示。
  这里不能用 `encoding/json` 整体序列化：它会把 `json.RawMessage` 重新压紧并转义 `< > &`，
  jsonb 文本里本来就带空格，一过它就不再逐字节相同，对拍永远过不去。
- 可空列写 `null`，与 events 的 NULL 一一对应，不会把 NULL 折成空串。
- 能压小就用 zstd；压不小（已经压过的数据、太短的块）就退化 `codec=0` 存原文，读端按 `codec` 分辨。

**读的硬上限**（都在解压之前判断，不按头部声明的大小分配内存）：

| 上限 | 值 | 行为 |
|---|---|---|
| `plainLen` | 16 MiB（`MaxPlainLen`） | 超出直接报错，解码器也设了同样的上限 |
| `count` | 8192（`MaxCount`） | 超出直接报错 |
| 单条事件 | 4 MiB（`MaxEventBytes`） | 构建时跳过并计数，不进冷块 |

解压后核对 `sha256(明文)` 与 `plainLen`，再按 `\n` 切行、逐行反序列化并核对条数。
任何一项不符都返回错误、返回 `nil` 事件列表，**不返回部分结果**。空块（0 条）不允许写入。

## 3. 两张新表

`EnsureSchema` 只建这两张表（`CREATE TABLE IF NOT EXISTS`，幂等）：

```
event_archive_chunks(id pk, run_id, seq, day, class_uid, source, first_ts, last_ts,
                     event_count, format, codec, plain_len, payload_len, plain_sha256,
                     payload, created_at, UNIQUE(run_id, seq))
  索引：(day, class_uid, source)、 (first_ts, last_ts)
event_archive_runs(id pk, started_at, finished_at, status, day_from, day_to, classes, sources,
                   scanned, archived, pinned_skipped, chunks, error, detail)
```

- **没有任何指向 events 的外键**，也没有触发器：冷归档与 events 之间只有「某一轮扫描时读到过」的关系，
  由 `run_id` + 对拍来证明，不靠数据库约束。
- `payload` 允许 TOAST，不给大字段建索引；`(day, class_uid, source)` 是阶段 B 定位块的入口，
  `(first_ts, last_ts)` 用于按时间窗挑块。
- `status`：`building`（构建结束、等对拍）→ `verified`（对拍通过）；构建或对拍出错记 `failed`，
  原因写 `error`。`detail` 记 `scanned`、候选与归档的首末 ts、超限事件 id、封块阈值等，供后续阶段对拍。

## 4. 影子构建

```
DATABASE_URL=... eventarchive shadow -from 2026-09-01 -to 2026-09-14 [-classes 4001,4003] \
    [-sources agent,sensor] [-chunk-events 2048] [-chunk-bytes 1048576] -confirm
```

1. 不加 `-confirm` 直接拒绝（与 `eventpartition` 同一约定，没有演练模式）。
2. 建 run 行，`status=building`。
3. **只读**扫描 events：`ts >= from AND ts < to+1d`、`class_uid = ANY(classes)`、`source = ANY(sources)`，
   并**排除被钉住的事件**（`id NOT IN (eventpart.PinnedIDs)`）。
4. 按 `ChunkEvents`（默认 2048）或 `ChunkBytes`（默认 1 MiB 未压缩）封块；每块编码后在一个事务里
   写 `event_archive_chunks` 并累加 run 的 `archived` / `chunks`。
5. 扫描结束写 `scanned` / `pinned_skipped` / `detail` / `finished_at`，`status` 保持 `building`，
   等 `verify` 置 `verified`。

**pin 排除先于归档判定**：被 `alerts.event_id`、`temporal_evidence.event_id`、
`temporal_detections.anchor_id`（`alert_id` 非空）引用的事件不归档，计入 `pinned_skipped`。
口径直接复用 `eventpart.PinnedIDs`（与保留期退役、janitor 逐行清理同一个常量），不另维护一份。

**分组的顺序与封块**：分块以 `(day, class_uid, source)` 为界——块上的这三列必须是同一个值，
否则阶段 B 按这三列定位会取到混杂的块。扫描因此按 `(类别, 来源)` 分组，每组内 `ORDER BY ts, id`
用 keyset 分页（`LIMIT`，每批 1000 行）流式读取：内存里只有一批事件加正在封的块，不把全量读进内存。
组内 ts 递增，所以日切换天然连续，到日边界就封块。

**超大事件**：单条编码后超过 `ChunkBytes` 时单独成块；但单条超过 4 MiB 时跳过，
计入 `detail.oversized` 并记下 id（最多 20 个），不静默丢。这类事件是阶段 A 的已知缺口。

**一致性与锁**：整个扫描固定在一个只读 `REPEATABLE READ` 事务的快照里，不给 events 加任何锁，
也不阻塞写入。快照内的计数与逐行读取因此自洽，构建结束时会核对一条不变量：

```
scanned == archived + pinned_skipped + oversized
```

对不上就让这轮 `failed`——宁可重跑，也不留一份解释不清的归档。快照之外的并发写入（构建开始之后
才入库的事件）不在本轮口径内，由 `verify` 报成「候选集已变化」。

**口径固定**：没给 `-sources` 时，构建开始时把范围内的来源清单固定下来写进 run 行，
`verify` 用同一份清单重查。之后新增的来源不会被悄悄纳入。

## 5. 对拍

```
DATABASE_URL=... eventarchive verify -run <uuid>
```

1. 先核 run 自己的账：`chunks` / `archived` 与 `event_archive_chunks` 实际行数、条数必须一致。
2. 按 run 的 `day_from/day_to/classes/sources` 只读重查候选集（同样排除 pin），
   与按 `seq` 顺序解码出的所有事件**逐事件全字段比对**：`id`、`ts`、`class_uid`、`source`、
   `asset_id`、`process_guid`、`parent_process_guid`、`username`、`conn_tuple`、`raw`（逐字节）。
   两侧顺序完全一致（类别、来源、ts、id 升序），所以边扫边比，内存里只有一批事件加一块冷块。
3. 每块解出来后还核一次块自身的自洽：`event_count` 与解出条数、块内同属一个 (日, 类别, 来源)、
   `first_ts` / `last_ts` 与首末条一致、块内 ts 不回退。
4. 全部一致才把 run 置 `verified`。

错误分三类，不混在一起：

| 情况 | 错误 |
|---|---|
| events 里多出候选（构建后新写入） | `候选集已变化，请重新运行` + 首个多出的事件 |
| 冷块里有、events 里已经没有（构建后被清理） | 同上 + 首个缺失的事件 |
| 同一个 id 的字段不一致、`raw` 字节不同、SHA 不符、解压失败 | 字段级差异或「冷块已损坏」，**不**说是候选集变化 |

单条编码后超过 4 MiB 的事件在两边同规则跳过（它们本来就不在冷块里），不是遗漏。

## 6. 空间度量

```
DATABASE_URL=... eventarchive report -run <uuid>
```

所有数字来自真实查询：

- **归档前**：被归档事件在 events 里还剩多少条、整行字节 `sum(pg_column_size(t.*))`；
  它们所在日分区的 `pg_total_relation_size`。
- **归档后**：`sum(plain_len)`、`sum(payload_len)`、`ratio = sum(plain_len)/sum(payload_len)`；
  `pg_total_relation_size('event_archive_chunks')`（含 TOAST 与索引，另附表/索引拆分）。
- 同时给出「events 日分区合计 vs `event_archive_chunks` 总大小」这组含索引的对比。

两个口径要注意：

- `sum(pg_column_size(t.*))` 是 jsonb 在库里的**二进制**行宽，`plain_len` 是 JSON **文本**字节数，
  两者不是同一个分母（文本通常更大）。压缩比只按 `plain_len/payload_len` 算。
- 日分区大小是**整分区口径**：包含当天没归档的类别、全部索引与空闲空间，
  与冷归档表不是同一批事件。这组数字只作量级参考，不能当成「省了多少空间」的结论。

阶段 A 不删 events，所以归档前后的空间是**叠加**的：真正释放空间要等阶段 C。

示例（测试库，3000 条 4001 事件、跨 2 天、两个 source、外带 1 条被钉住事件与外带 1 条 1007；
run `b9dd5453`）：

```
候选 3001 条：归档 3000 条 / 被钉住跳过 1 条
冷归档：4 块 / 3000 条事件
  未压缩明文 sum(plain_len) = 1702090 字节（1.62 MiB）
  实际载荷 sum(payload_len) = 103334 字节（100.91 KiB）
  压缩比 ratio = sum(plain_len)/sum(payload_len) = 16.47x
  event_archive_chunks 总大小 270336 字节（264.00 KiB，含 TOAST 与索引：表 200.00 KiB + 索引 64.00 KiB）
events 侧（同一批被归档事件，仍在 events 里）：3000 条，整行 sum(pg_column_size(t.*)) = 1472064 字节（1.40 MiB）
  日分区合计（整分区口径）= 11542528 字节（11.01 MiB）
对比：events 日分区合计 11.01 MiB / event_archive_chunks 总大小 264.00 KiB = 42.70x
```

这批数据是脚本造的、重复度很高，16.47x 不代表生产压缩比；生产同构数据应以实跑结果为准，
命令与上面完全一致。同一批数据上再跑一轮 shadow（新的 run id）前后，`events` 的
`count(*)`、`sum(pg_column_size(t.*))` 与按 id 的全行 md5 摘要完全一致，分区清单也一字不差。

## 7. 命令行

```
DATABASE_URL=... eventarchive ensure-schema
DATABASE_URL=... eventarchive shadow -from 2026-09-01 -to 2026-09-14 [-classes …] [-sources …] -confirm
DATABASE_URL=... eventarchive verify -run <uuid>
DATABASE_URL=... eventarchive report -run <uuid>
```

`shadow` 会写库，不加 `-confirm` 拒绝；`verify` 只改 run 的状态列；`ensure-schema` 只建表。
失败一律非零退出码。与其他运维命令（`cmd/eventpartition`、`cmd/backtest`）一样，二进制要放进能连到
主库的环境里跑。

## 8. 已验证的内容

单元测试（`server/internal/eventarchive/chunk_test.go`，无 DB）：全字段往返（含 NULL 可空列、
带未转义 Unicode 与转义字符的 raw）、空块拒绝、头部 magic/format/codec/count/plainLen/sha 逐项篡改
必须报错且不 panic、载荷截断、`count` 与行数不符、超上限先拒绝后解码、不可压数据退化为 `codec=0`、
同样输入两次编码字节一致。

集成测试（`shadow_integration_test.go`，`-tags integration -p 1`）：`EnsureSchema` 幂等、
没有 `-confirm` 拒绝且不留 run 行、类别内且未钉住的事件进冷块（钉住 / 类别外 / 超大都不进）、
单条超过 `ChunkBytes` 的事件单独成块、对拍通过后置 `verified`、`payload` 改一字节后对拍失败、
构建后新写入报「候选集已变化」、影子归档前后 `events` 的 `count(*)` 与按 id 的 raw 摘要完全一致、
`ratio` 与手工 `sum(plain_len)/sum(payload_len)` 一致。

## 9. 已知限制与后续

- **事件不删、分区不动**：阶段 A 只证明「能正确编码与对拍」，不释放任何空间。
- **超大事件（> 4 MiB）不归档**：记在 `detail.oversized` 里，阶段 B 之前要想清楚是拆块还是留在热库。
- **同一范围可以重复跑**，每次一个新 `run_id`，冷块会叠加。去重/覆盖不在阶段 A 内，
  由运维按范围管理；阶段 C 之前应能按 run 回收（删 `event_archive_chunks` 里该 run 的行即可）。
- **对拍要求候选集不变**：构建期间大量写入时对拍会失败，这是设计上的如实报告，
  应在低峰期跑，或用较老的日期区间。
- **未接 server 启动、没有查询入口**：阶段 B 才加冷热读取，届时 `(day, class_uid, source)` 索引
  与 `first_ts/last_ts` 就是挑块的入口。
- **`report` 要解码全部冷块**：为了按 id 回查 events 的整行字节，它逐块解码取 id（顺带又校验了一遍
  块完整性），耗时与归档条数成正比；大 run 上先在低峰期跑。
