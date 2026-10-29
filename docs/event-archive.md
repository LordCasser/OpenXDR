# 冷归档

events 保留期内的数据在日分区里，过期分区由 `eventpart.Retire` 整体退役（见
`docs/event-partitioning.md`）。退役之外还有一类需求：**把过期但仍有价值的事件压成冷块长期保留**，
查询时按需解压。本文是冷归档的格式、口径与阶段划分；阶段 A（影子归档）、B1（冷热读取）、
B2（定位与物化）与 C（单日切换与恢复）已实现，**其中 C 只在测试库验证过**。

代码：`server/internal/eventarchive`（冷块编解码、影子构建、对拍、度量、单日切换与还原），
`server/internal/eventpart`（分区 DDL：预建、退役、单日重写），
`server/cmd/eventarchive`（命令行）。

## 1. 阶段划分

| 阶段 | 做什么 | 状态 |
|---|---|---|
| **A 影子归档** | 只读 events，把候选事件编码成冷块写进两张新表，逐事件对拍 + 度量 | **已实现** |
| **B1 冷热读取** | `/api/events` 先查热表，再按同一组参数与同一个组权限查冷块，合流去重；覆盖度用响应头如实标注 | **已实现** |
| **B2 定位与物化** | 每块带 ID Bloom filter；按事件 ID 定位（`Locate` / `Exists`）、证据物化（`Materialize`） | **已实现** |
| B2 生命周期 | 按 run 的回收与跨 run 覆盖度统计 | 未实现 |
| **C 单日切换与恢复** | `plan` → `swap` → `restore`：把已验证 run 覆盖的一天重建成只保留「钉住 + 非归档口径」的行，冷层继续可读、可整日还原；重传判重接进接入路径（`EVENT_ARCHIVE_DEDUP`，第 9 节） | **已实现（只在测试库验证）** |

阶段 A 的铁律：**不改动、删除或切换 events 的任何一行**。不改 `events` 与其索引，
不 `DETACH` / `ATTACH` / `DROP` 任何分区，不调用 `eventpart.Retire`，不给 events 加外键或触发器。
写入只发生在两张新建表上：`event_archive_chunks`、`event_archive_runs`。
正因为如此，阶段 A 无论跑多少轮都不影响线上读写路径，也不需要停写窗口或额外磁盘余量规划
（冷块本身要占空间，约等于归档范围的明文压缩后大小）。

阶段 B2 唯一的例外是 `Materialize`：它会往 `events` **插入**一条原本只在冷块里的事件
（`ON CONFLICT DO NOTHING`），插入缺失的证据是它的本意；仍然不修改、不删除既有行，也不碰分区。

阶段 C 是**唯一会删数据**的环节：它按天重建日分区，把已经进了冷块的行从热表移走。
第 9 节把它的口径、拒绝条件与事务边界写清楚；任何一条不满足就拒绝执行，不猜。

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

头部布局是冻结的：阶段 B2 的 ID Bloom filter 不进这套字节，它是块的一条**列**（`id_bloom`），
和 `first_ts` / `event_count` 一样属于「头部字段落在库里」的那部分，`MarshalBinary` 导出的字节流
不包含它。没有 filter 的块照旧能读、能查。

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
                     payload, id_bloom, created_at, UNIQUE(run_id, seq))
  索引：(day, class_uid, source)、 (first_ts, last_ts)
event_archive_runs(id pk, started_at, finished_at, status, day_from, day_to, classes, sources,
                   scanned, archived, pinned_skipped, chunks, error, detail)
```

- **没有任何指向 events 的外键**，也没有触发器：冷归档与 events 之间只有「某一轮扫描时读到过」的关系，
  由 `run_id` + 对拍来证明，不靠数据库约束。
- `payload` 允许 TOAST，不给大字段建索引；`(day, class_uid, source)` 是阶段 B 定位块的入口，
  `(first_ts, last_ts)` 用于按时间窗挑块。
- `id_bloom`（阶段 B2）是每块的 ID Bloom filter，**可空**：老库用幂等
  `ALTER TABLE … ADD COLUMN IF NOT EXISTS id_bloom bytea` 补上，已有列与约束一概不动，也不加
  `NOT NULL`。NULL 表示「这块没有过滤器」，按 ID 查时必须解压（见第 8 节）。
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

## 7. 读取契约（阶段 B1）

冷读只读，不改冷块格式、不动 events，也不改变热表查询的参数语义。

**开关**：`EVENT_ARCHIVE_READ=1` 才把 `*sql.DB` 交给 `/api/events`，默认关闭。
开启时启动阶段先跑一次 `EnsureSchema`；建表失败只记警告并降级为「没有冷层」，
不让事件页因为冷归档起不来就整页报错。开关关着（连接为 nil）时，响应与改动前逐字节一致。

**候选块收窄**：按块元数据收窄——时间窗用块上的 `first_ts` / `last_ts`（块与 `[From, To)` 有交集
等价于 `last_ts >= From AND first_ts < To`），再叠加 `class_uid` 与 `source`；`day` 就是块内事件的
UTC 日，被时间窗完全覆盖，所以不单独传日期参数（也就不引入 date/timestamptz 的隐式转换）。
`event_archive_chunks_ts` 与 `event_archive_chunks_day` 两个索引服务这两个方向。
块与事件在 Go 侧用同一套条件再筛一次，任何来源都绕不过时间窗与类别、来源。

**`eventarchive.Query`**：

```go
Query(ctx context.Context, db *sql.DB, f Filter) ([]Event, Coverage, error)
```

| 条件 | 含义 |
|---|---|
| `From` / `To` | 按 `ts`，左闭右开 |
| `AssetIDs` | **nil 表示不限**（全局 admin）；**非 nil 表示受限**：事件 `asset_id` 为 NULL 或不在集合里的一律丢弃，空切片表示「一无所见」，直接返回空结果。与热表 `AssetIDIn()` 的空集合口径一致，没有可见资产的用户不能因为传了空集合就变成不限 |
| `Classes` / `Sources` | 空表示不限 |
| `IDs` | 按事件 ID 精确定位，可与其它条件叠加；ID 不在块元数据里，只能靠时间窗与类别先收窄 |
| `Limit` | `<=0` 用 1000 |

- 结果是 `(ts, id)` 倒序、按 `(ts, id)` 去重（同一轮或多轮 run 重复归档同一事件时只留一条），最多 `Limit` 条。
- **预算**：单次最多解压 200 块（`maxScannedChunks`）。每块都要整块解压，不设上限时一个宽时间窗会把
  整个归档读进内存；用完预算就停，并把 `Coverage.Truncated` 置真。
- **内存**：候选块只取元数据，载荷一块一块取；命中的事件只在内存里保留 `Limit` 条（小顶堆），
  被挤掉的条数记进 `Coverage.Matched` 与 `Truncated`。
- **块损坏**：头部/`sha256`/条数/块内 (日, 类别, 来源) 与首末 ts 任一不符，`Query` **整体返回错误**
  并带块 id，不返回部分结果——「跳过坏块」等于把「查不到」伪装成「不存在」。
- **表不存在**：返回 `ErrNoSchema`（不是数据错误，是部署状态）；**表在但没有块**：返回空结果、不报错。

**`/api/events` 合流**：

1. 热表查询与参数语义完全不变（`from` / `to` / `assetId` / `classUid` / `source` / `q` / `limit`，
   默认 24 小时，取满上限带 `X-Truncated`）。
2. 冷查询用同一组参数构造 `Filter`：`From`/`To` 取同一对时间，`To` 补 1ns——热表是 `ts <= to`，
   冷查询是左闭右开，补一个纳秒才不会漏掉恰好等于 `to` 的事件；`assetId` / `classUid` / `source`
   逐项对应；`Limit` 与热表相同。
3. 权限用同一个 `scope`：`s.all` 传 `nil`（不限），否则传 `s.assets`（受限，可能是空集合）。
   `assetId` 与 scope 同时生效：资产不在可见范围时交集为空，冷热两边都返回空。
4. 合流：热表行优先（它带着告警与自动化信息），冷块事件补进来，按 `(ts, id)` 去重、倒序、截到 `limit`。
   冷块为空时原样返回热表结果，不重排、不截断。
5. 关键词（`q`）**跳过冷查询**：冷块没有关键词索引，逐块解压全文扫的代价与窗口大小无关、不可控。

**覆盖度**（`X-Archive-Coverage`）：调用方据此区分「查过、没有」与「没查」。

| 情形 | 响应头 |
|---|---|
| 冷读开关关闭（连接为 nil），或归档表在但没有块 | 不写这个头，响应与改动前逐字节一致 |
| 开关开着但库里没有冷归档表 | `skipped=no-schema` |
| 归档有数据、关键词查询 | `skipped=keyword` |
| 归档有数据、查询窗口整体早于最早一块冷数据 | `skipped=before_archive` |
| 已执行冷读 | `chunks=<扫过的块数>;matched=<冷层命中去重后条数>;truncated=<0 或 1>` |

- `chunks>0 && matched=0` 是真实的「查过、没有」，与「没查」严格区分。
- `matched` 是**冷层**的命中数（含与热表重复的事件），不是合流后的新增条数。
- `truncated=1` 表示冷层结果被截断：命中数超过 `limit`，或有候选块因 200 块预算没扫。
- 冷块解码失败、读块出错等真实错误：`500` 并带块 id，**不降级**成只返回热表结果。

## 8. 按 ID 定位与证据物化（阶段 B2）

B1 的冷读只能按时间窗、类别、来源收窄：块元数据里没有 ID 索引。阶段 C 要拿冷块支撑两件事——
**证据物化**（冷事件重新成为证据）与**重传判重**（这条事件是不是已经归档过）——都得先能按事件 ID
找一条冷事件。逐块解压全文扫在生产上不可接受，所以给每块加一个 ID Bloom filter，
它只负责**排除不可能命中的块**；命中仍必须解压并逐事件精确比对 ID。

本阶段只提供库函数与 CLI：`Locate` / `Exists` / `Materialize` 自己不接接入热路径，
`grpcsvc` 与 `ingest` 的处理链都不 import 本包。重传判重的接线在第 9 节（阶段 C）：
接入路径只通过 `main.go` 的适配器调用 `Exists` 与下面这个边界查询。

### ID Bloom filter

| 项 | 值 |
|---|---|
| 落库列 | `event_archive_chunks.id_bloom`（可空 `bytea`） |
| 位宽 | 10 bit/事件（`BloomBits`），最小 64 字节，按 8 字节对齐 |
| hash | 3 个：`sha256(id)` 前两段 + FNV-1a 64，各自对 bit 数取模 |
| 编码 | 就是位图本身：bit 数 = `len(bloom)*8`，不另存长度或版本 |
| 没有过滤器 | `nil` / 空 / 长度不是 8 字节对齐 → `MayContainID` 恒为 true |
| 假阳性 | 理论 ≈1.7%（`(1-e^{-3/10})^3`），只意味着多重解压几块 |

**零漏报由构造保证，不靠调参**：
1. 只置位、从不复位，filter 里只有「写进去的 id 的位」；
2. bit 数只由 `len(bloom)` 推出，写端（`BuildIDBloom`）与读端（`MayContainID`）共用同一套
   `bloomPositions`，不存在「写时算一个位、读时算另一个位」的可能；
3. 位宽不够只会抬高假阳性率，不会漏报；`ids` 比声明条数多时按实际条数取大，宁可 filter 大一点。

唯一能导致漏报的是 filter 本身被截断或改坏，所以长度不合约定一律按「没有过滤器」处理——退回
解压后精确比对，代价只是慢，不会给出错误结论。

**老块**（`id_bloom IS NULL`，阶段 B2 之前写的）照旧能读、能查：`MayContainID(nil, …)` 恒为 true，
所有老块都进入候选，只是多解压几块。新块（`shadow` 写的）一定带 filter。

### `Locate` / `Exists`

```go
Locate(ctx context.Context, db *sql.DB, id uuid.UUID) (Event, bool, error)
Exists(ctx context.Context, db *sql.DB, id uuid.UUID) (bool, error)
```

候选块按 `(first_ts, last_ts, id)` 倒序取（新块优先）：`id_bloom` 非空的先用 `MayContainID` 排掉，
NULL 的一律进入候选；通过 filter 的块逐块解压、核对块自洽（`event_count`、块内 (日, 类别, 来源)、
首末 ts），再**逐事件精确比对 ID**，命中即返回。

结论分三档，调用方必须分清：

| 情形 | 返回 |
|---|---|
| 命中 | `found=true` + 事件（同一条事件被多轮 run 归档时取最新一块的副本） |
| 全部候选块都解压比对过、确实没有 | `found=false, err=nil` |
| 通过 filter 的候选块超过预算（200 块，`maxScannedChunks`） | `ErrChunkBudget`，**不能**当「不存在」 |
| 冷归档表不存在（没跑过 `ensure-schema`） | `ErrNoSchema`（部署状态，不是数据错误） |
| 块损坏 / 块头与内容不符 | 错误并带块 id，**不返回** `found=false` |

**超预算必须报错**：`found=false` 的含义是「已经证明冷层没有」，而预算是硬上限（每块都要整块解压，
zstd frame 不支持随机访问）。超预算还返回 false，重传判重就会把老事件当成新事件、重复告警，
正好是 Bloom 要防的那类事故。命中优先：命中在预算内直接返回，`ErrChunkBudget` 只在「没命中」时报出。

`Exists` 只是 `Locate` 的包装，错误语义完全相同——重传判重只接受「false 就一定能确定没有」的口径。

### `Boundary`

```go
Boundary(ctx context.Context, db *sql.DB) (last time.Time, ok bool, err error)
```

返回冷层最晚的事件时间（`max(last_ts)`）与「是否已经有冷块」。它是接入路径**时间闸门**的唯一依据：
事件时间晚于这个边界就不可能在冷块里，连 `Exists` 都不用发。

- 只读一条聚合：不解压、不读 `id_bloom`、不缓存（缓存是调用方的事，见第 9 节接线）。
  一次调用是一次 `max(last_ts)` 聚合（与事件条数无关），导入侧每 60 秒每个节点才查一次；
- 冷层没有表返回 `ErrNoSchema`（部署状态）；`ok=false` 只表示还没有任何块；
- 边界只会随新归档向后移动，`swap` / `restore` 都不改变它（它们不动冷块）。

### `Materialize`

```go
Materialize(ctx context.Context, db *sql.DB, id uuid.UUID) (inserted bool, err error)
```

把一条冷事件物化回 `events` 普通行，供「冷事件重新成为证据」时使用。

- 用 `Locate` 取事件；冷层没有返回 `(false, nil)`，**不插入任何行**。它与「events 里本来就有」的
  返回值相同，要区分两者另查一次 `Locate` / `Exists`。
- 单事务里一条 `INSERT INTO events (id, ts, class_uid, source, asset_id, process_guid,
  parent_process_guid, username, conn_tuple, raw) VALUES (…) ON CONFLICT DO NOTHING`；
  `RowsAffected()==0` 即 `inserted=false`。并发重复物化最多插一行，不覆盖 events 里已有的行。
- **不经过检测器**：不产规则命中、不产告警、不改 `temporal_*` / `identity_*` 等任何派生表——
  物化是复制，不是重放。
- 冷块保持不可变：不回写、不删块、不改 run。
- events 自己的约束照旧生效：`asset_id` 的 foreign key 与分区路由由数据库判定，目标资产已被删除时
  报错，不静默丢字段。恰好落在默认分区还是日分区，由 `ts` 决定。

### 命令行

```
DATABASE_URL=... eventarchive locate -id <uuid>
DATABASE_URL=... eventarchive materialize -id <uuid> -confirm
```

`locate` 只读，打印 found / ts / class_uid / source / asset_id 与是否在冷块中命中；
`materialize` 会往 events 插入一行，不加 `-confirm` 直接拒绝，打印 inserted 与幂等说明
（`inserted=false` 时用 `Locate` 分清是「events 里已有」还是「冷层没有」）。

## 9. 单日切换与恢复（阶段 C）

阶段 A/B 做完之后，同一批事件在 `events` 与冷块里各有一份；阶段 C 才把它们从热表移走，
于是空间真正释放。这是全项目唯一删数据的环节，所以拆成三步，**先看计划，再动数据**：

```go
type SwapPlan struct {
    Day        time.Time // UTC 日
    Archived   int64     // 该日、本 run 覆盖的类别/来源、且未被 pin 的行数（将被移出热表）
    KeepPinned int64     // 该日被 pin 保护的行数（无论类别/来源）
    KeepOther  int64     // 该日其它类别/来源的行数
    Total      int64     // 该日分区当前总行数
}
Plan(ctx, db, runID, day) (SwapPlan, error)        // 只读
Swap(ctx, db, runID, day) (SwapPlan, error)        // 重建该日分区（会删行）
Restore(ctx, db, runID, day) (int64, error)        // 把该日冷事件物化回 events（幂等）
```

分区 DDL 属于 `eventpart`，不在本包：`Swap` 把保留口径交给
`eventpart.RewriteDay(ctx, db, day, keepSelect) (kept, dropped, err)`，由它在一个事务里重建分区。

### 保留口径与归档口径互补

`Swap` 用的 `keepSelect` 与阶段 A 的归档口径是同一份谓词的互补，**两边共用
`eventarchive.scopePredicate(run)` 这一份 SQL 字面量**，不各写一遍：

```
归档（阶段 A 扫的候选，排除 pin）
  id NOT IN (PinnedIDs) AND (class_uid = ANY(classes) AND source = ANY(sources))

保留（阶段 C 的 keepSelect）
  SELECT id FROM events_pYYYYMMDD
   WHERE id IN (PinnedIDs) OR NOT (class_uid = ANY(classes) AND source = ANY(sources))
```

`PinnedIDs` 就是 `eventpart.PinnedIDs`（`alerts.event_id` ∪ `temporal_evidence.event_id` ∪
已出告警的 `temporal_detections.anchor_id`），与影子构建、保留期退役、janitor 用的是同一个常量。

三条互斥的判定把分区的每一行**恰好**分进一个桶，所以
`Archived + KeepPinned + KeepOther == Total` 是构造出来的等式，不是巧合：

| 行 | 条件 | 桶 | 去向 |
|---|---|---|---|
| 被 pin | `id IN (PinnedIDs)` | `KeepPinned` | 留在热表 |
| 口径内未 pin | 非 pin 且 `inScope` | `Archived` | 移出热表（冷块里有副本） |
| 口径外 | 非 pin 且 `NOT inScope` | `KeepOther` | 留在热表 |

每个桶都是同一张分区表上互斥的 `count(*) FILTER (…)`，`Plan` 还会再断言一次三者之和等于
`count(*)`。`RewriteDay` 在重建事务里用同一个 `keepSelect` 再数一遍保留集，与暂存表实际行数比对；
`Swap` 再把这次实际得到的 `kept/dropped` 与计划核对——计划与执行不一致就直接报错，不静默接受。

### 拒绝条件（任一不满足就拒绝，一个字节都不动）

| 条件 | 为什么 |
|---|---|
| run 不存在，或 `status != verified` | 没对拍通过的归档不能当删除依据 |
| `day` 不在 run 的 `day_from..day_to` 内 | 范围外的一天没有「本 run 的归档」可言 |
| 该日没有独立日分区（行在 `events_default`） | 本流程**不**去默认分区搬行，报错要求先 `EnsureDays` 建好日分区 |
| `Plan.Archived == 0` | 没有要移出的行，不该为 0 条重建分区 |
| 该日冷块的 `sum(event_count)` 与 `Archived` 不相等 | 要删的条数必须等于真正落到冷块里的条数 |

最后一条是最关键的安全网：阶段 A 会跳过单条编码后超过 4 MiB 的事件（记在
`detail.oversized`），这类事件在热表里、却不在冷块里。若按口径直接删，它们就永久丢了。
同样，对拍之后新写入的迟到事件也会让这个数变大。两种情况下 `Swap` 都拒绝并报出差额。

### 事务边界：为什么中途失败不会留下半个分区

`eventpart.RewriteDay` 照 `retireDay` 的模式，全部动作在一个 `sql.Tx` 里：

1. `SET LOCAL lock_timeout = '3s'`，对日分区 `LOCK TABLE … IN SHARE MODE`
   （读照常，写入该日的迟到事件等待；等不到锁就放弃）；
2. `CREATE TABLE events_pYYYYMMDD_rewrite (LIKE events INCLUDING DEFAULTS)`；
3. `INSERT … SELECT` 复制保留行，再用私有 `cloneIndexes` 建好同构索引
   （与 `retireDay` 共用同一份实现，不在排他锁窗口里现建索引）；
4. 独立数一遍 `keepSelect` 的行数，与暂存表实际行数不符即中止；
5. 按 `derived` 列表清掉被删事件的派生状态（删分区不触发逐行级联触发器，必须显式做，
   与 `retireDay` 同一清单）；
6. `DETACH` → `DROP TABLE` → `RENAME` → `ATTACH`，全部在同一事务里。

PostgreSQL 的 DDL 是事务性的：任何一步失败（暂存表名被占、索引建不起来、`DROP` 有依赖、
`ATTACH` 校验不通过、客户端断开）都会整体回滚，旧分区连同它的索引、触发器、分区边界原样保留，
中途建出来的暂存表也一并消失。不 `TRUNCATE`、不 `DELETE FROM events`：逐行删除会触发证据保护
与级联触发器，代价与语义都不是这里要的。ATTACH 之后新分区自动带上父表的两个行级触发器
（`openxdr_events_release` / `openxdr_events_evidence`）。

### 还原

`Restore` 按 `seq` 遍历该 run 在该日的冷块，逐条解出事件后调用既有的
`Materialize`（`Locate` + 单事务 `INSERT … ON CONFLICT DO NOTHING`），返回**实际插入**的行数：

- 只碰这个 `run_id` + 这个 `day` 的块，不涉及别的 run、别的日子；
- 已存在的事件不计，所以重复执行第二次返回 0（幂等），可以安全地重试；
- 不经过检测器：不产规则命中、不产告警、不改 `temporal_*` / `identity_*`；
- 冷块保持不可变（不回写、不删块、不改 run），还原只是把冷副本再复制一份到热表。

### 命令行

```
DATABASE_URL=... eventarchive plan    -run <uuid> -day YYYY-MM-DD
DATABASE_URL=... eventarchive swap    -run <uuid> -day YYYY-MM-DD -confirm
DATABASE_URL=... eventarchive restore -run <uuid> -day YYYY-MM-DD -confirm
```

`plan` 只读并打印四个计数与「swap 会不会拒绝」的原因；`swap` / `restore` 不带 `-confirm`
直接拒绝并非零退出（没有演练模式）。`swap` 成功后把这次的结果合并进 run 的
`detail.swapped`（`day`、`archived`、`keep_pinned`、`keep_other`、`total`、`at`），
**不改 `status`**；结果与计划不符时也会写一条带 `note` 的记录再报错。

### 重传判重接线（`EVENT_ARCHIVE_DEDUP`）

`swap` 把行移出热表之后，`INSERT ... ON CONFLICT DO NOTHING` 再也看不到它们：迟到或重传的
老事件会被当成新事件重新入库、重新检测。`EVENT_ARCHIVE_DEDUP=1` 才把冷层的存在性判断接进
接入路径（`ingest.Processor.Archive`，默认 `nil`，不设时接入路径一行都不多跑）。

**依赖方向**：`ingest` 不 import `eventarchive`，只定义最小接口 `ingest.ArchiveDedup`
（`Archived` + `ArchiveBoundary`），适配器在 `main.go`；`eventarchive` 不知道自己在被谁调用。

**时间闸门 + 60 秒缓存**：`events` 接入峰值约 3000 条/秒，`Exists` 要扫一遍
`event_archive_chunks` 的元数据，逐条查不可接受。归档只覆盖较老的日子，所以只有
`envelope.Timestamp <= 归档中最晚的 last_ts` 时才查冷层；边界走 `ingest.CachedArchive`
的 60 秒 TTL，缓存未命中或过期才查一次 `eventarchive.Boundary`。缓存放 `ingest` 侧而不是
`eventarchive`：边界是接入热路径的准入判断，而 `eventarchive` 的读函数保持无状态，
一份会过期的边界不能被冷读、覆盖度统计或证据物化复用。

**插入点：先查后插，紧接在 `INSERT ... ON CONFLICT` 之前**。命中冷层就按重复处理
（`stored=false`，不入库、不检测、不产告警）。不选「插入后再删」：插入再删有一段窗口让行
重新可见，而且检测副作用（告警、时序命中、身份观测）已经发生，删掉事件行回滚不了它们。

竞态：`RewriteDay` 在重建事务里先对该日分区加 `SHARE` 锁，冷块在 `shadow` + `verify`
阶段就已写好、与切换无关，所以判定读到的是切换前或切换后的确定状态。读到「已归档」→ 本次
不入库，该日分区随后也只会移走这一行；读到「不在归档」→ 这条事件不在 run 口径内（类别/来源
之外，或仍被 `alerts` 等钉在热表里），`Swap` 不会移走它，插入照常成立。只有「口径内、未 pin、
闸门通过之后恰好被同一次切换带走」这一瞬间的插入会随分区重建消失——副本仍在冷块里，下一次
重传会被判为已归档，数据不丢。

**失败策略：fail-open**。`Archived` 返回错误（块损坏、`ErrChunkBudget`、库不可用）或边界读不到时，
照常入库并继续检测：

- 把「无法确认」当成「已归档」会**永久丢掉一条真实事件**；重复告警最多被告警侧去重窗口吸收，
  丢事件不可恢复。这个方向不能反。
- 每次 fail-open 都计入 `openxdr_archive_dedup_failopen_total{stage}`（`boundary` 边界查询、
  `lookup` 按 ID 定位）；`slog.Warn` 带事件 id 与原因，同一原因每分钟最多一条。
- 边界查询失败也会被缓存到过期（60 秒），不会因为冷层故障让每条事件都去查库；
  调用方自己的 ctx 取消不写缓存。
- 冷归档表不存在（没跑过 `ensure-schema`）同样落在 fail-open：启动日志会说明，指标里
  `stage=boundary` 会增长；server 不替 CLI 建冷归档表。

**运营不变式**：

1. **一旦开始用 `eventarchive swap` 切走分区，server 的 `EVENT_ARCHIVE_DEDUP` 必须为 `1`。**
   否则重放会产生重复事件行与重复告警。`cmd/eventarchive swap` 的成功输出会提醒这一点
   （CLI 读不到 server 的环境变量，只陈述要求）。
2. 与 `EVENT_ARCHIVE_READ` **相互独立**：一个管 `/api/events` 的冷读，一个管接入判重，各开各的。
3. 切换后最多 60 秒内，各节点缓存的边界仍是旧值；这段时间里重放刚被切走的事件会像接线前一样
   重新入库（不会反过来丢事件）。低峰手工切换时，切完等一个缓存周期即可。

**这条判重实际覆盖哪些事件**：被 `alerts` / 时序证据钉住的事件不进冷块、也不被 `swap` 移走，
它们的重放仍由 `ON CONFLICT` 挡住。真正依赖冷层判重的是「归档时没有告警」的旧事件——重放的
危害是规则后来上线或收紧后，同一条老事件被重新检测、产出一条本不该有的新告警；同时事件行会
重新占回热表（并在下次归档时再进一次冷块）。

## 10. 命令行

```
DATABASE_URL=... eventarchive ensure-schema
DATABASE_URL=... eventarchive shadow -from 2026-09-01 -to 2026-09-14 [-classes …] [-sources …] -confirm
DATABASE_URL=... eventarchive verify -run <uuid>
DATABASE_URL=... eventarchive report -run <uuid>
DATABASE_URL=... eventarchive locate -id <uuid>
DATABASE_URL=... eventarchive materialize -id <uuid> -confirm
DATABASE_URL=... eventarchive plan -run <uuid> -day YYYY-MM-DD
DATABASE_URL=... eventarchive swap -run <uuid> -day YYYY-MM-DD -confirm
DATABASE_URL=... eventarchive restore -run <uuid> -day YYYY-MM-DD -confirm
```

`shadow` / `materialize` / `swap` / `restore` 会写库，不加 `-confirm` 拒绝；`verify` 只改 run 的状态列；
`ensure-schema` 只建表；`locate` / `plan` 只读。失败一律非零退出码。与其他运维命令
（`cmd/eventpartition`、`cmd/backtest`）一样，二进制要放进能连到主库的环境里跑。

## 11. 已验证的内容

单元测试（`server/internal/eventarchive/chunk_test.go`，无 DB）：全字段往返（含 NULL 可空列、
带未转义 Unicode 与转义字符的 raw）、空块拒绝、头部 magic/format/codec/count/plainLen/sha 逐项篡改
必须报错且不 panic、载荷截断、`count` 与行数不符、超上限先拒绝后解码、不可压数据退化为 `codec=0`、
同样输入两次编码字节一致。

集成测试（`shadow_integration_test.go`，`-tags integration -p 1`）：`EnsureSchema` 幂等、
没有 `-confirm` 拒绝且不留 run 行、类别内且未钉住的事件进冷块（钉住 / 类别外 / 超大都不进）、
单条超过 `ChunkBytes` 的事件单独成块、对拍通过后置 `verified`、`payload` 改一字节后对拍失败、
构建后新写入报「候选集已变化」、影子归档前后 `events` 的 `count(*)` 与按 id 的 raw 摘要完全一致、
`ratio` 与手工 `sum(plain_len)/sum(payload_len)` 一致。

读取（阶段 B1）：

- 单元（`query_test.go`，无 DB，用内存块）：时间/类别/来源/ID 过滤（含左闭右开边界）、
  `AssetIDs` 的 nil 与空集合两种语义（NULL 资产被排除、集合外被排除、空集合一无所见）、
  `(ts, id)` 去重与倒序、`Limit` 截断、坏块整体报错并带块 id、块头与内容不符报错、
  200 块预算、窗口外的块连解压都不发生。
- 集成（`query_integration_test.go`）：影子归档后用 `Query` 读回（顺序、raw 与 events 逐字节一致）、
  资产集合过滤、块损坏报错带块 id、表在但无块、表不存在的 `ErrNoSchema`。
- 接口（`events_archive_integration_test.go`）：热冷合流（只存在于冷块的事件也返回、重复归档只留一条、
  热表优先取原文）、组权限（admin 看到全部，组内 viewer 只见本组资产，没有组时一无所见，
  组外资产筛选冷热都为空）、覆盖度头（`chunks/matched/truncated`、`limit` 截断时 `truncated=1`
  且带 `X-Truncated`、`skipped=keyword` 且不返回冷数据、`skipped=before_archive`）、坏块 500 带块 id、
  冷层不可用时响应逐字节不变（连接为 nil / 表不存在 / 表为空三种情形）。

定位与物化（阶段 B2）：

- 单元（`lookup_test.go`，无 DB）：
  - **零漏报**：n=1..5000 每个块大小逐条断言 `MayContainID` 为 true（约 1250 万次查询）；
    另在 n=1 / 2 / 51 / 52（64 字节进位边界）/ 2048 / 8192、全零 id 集、仅末位不同的 id 集上重复一遍。
  - 假阳性率：8192 条事件的块上测 10 万个确定不在块里的 id，实测 **1.550%**（< 2% 上界，
    同时断言排除率不是 0，否则 filter 形同虚设）。
  - `bloom == nil`、空字节、7/63/65 字节（非 8 字节对齐）一律返回 true（必须解压）；
    全零 filter 必须返回 false（证明排除真的发生）。
  - 编码约定：长度按 10 bit/事件 + 8 字节对齐算出、不小于 64 字节、装得下全部 id、
    同输入两次字节一致、拷贝后仍能查到每条 id。
- 集成（`lookup_integration_test.go`）：
  - `Locate` 命中：字段全填 / 可空字段全 NULL / 另一个来源三条事件都能按 ID 找到，
    并与 events 的行**逐字段一致**（raw 逐字节）；另逐个解块断言 `id_bloom` 覆盖块内全部事件，
    以及加列后 B1 的 `Query` 与阶段 A 的 `Verify` 仍然通过。
  - `Locate` 未命中返回 `(false, nil)`；表在但无块同样；表不存在返回 `ErrNoSchema`。
  - 老块（`id_bloom` 全部置 NULL）仍能按 ID 命中且字段一致。
  - 块损坏返回错误并带块 id，`found=false` 与 `ErrChunkBudget` 都不成立。
  - 201 块超预算：带 filter 时全部被排除、结论是确定的「没有」；置为老块后返回
    `ErrChunkBudget`（`errors.Is` 成立，信息含「预算」），而候选顺序最前面的那条事件仍优先命中。
  - `Materialize` 幂等：删掉 events 行后第一次 `inserted=true`、第二次 `false`，
    events 里恰好一行且与原事件逐字段一致，冷块的整行摘要前后不变。
  - `Materialize` 无副作用：先造一条基线告警，物化前后 `alerts` 与 5 张 `temporal_*` 的计数完全不变。
  - `Materialize` 对不存在的事件不插入任何行、不报错。
- 命令行：`locate` 命中/不命中与 `materialize` 的 `-confirm` 拒绝、首次插入、二次幂等
  （在测试库上实跑，输出见本次交付）。

切换与恢复（阶段 C，`swap_integration_test.go`，`-tags integration -p 1`）：

- `Plan` 计数自洽：夹具是一天 7 行（4 条归档候选含另一个来源、1 条被 alerts 钉住、1 条类别外、
  1 条来源外），断言 `Archived=4 / KeepPinned=1 / KeepOther=2 / Total=7`、三桶之和等于分区行数、
  `Archived` 与解出的冷块内容一致，且 `Plan` 前后 `events` 的全行摘要不变（确实只读）。
- `Swap` 只动该动的行：切换后分区行数 == `KeepPinned + KeepOther`；4 条被移出的 id 在 `events` 里
  查不到；钉住 / 类别外 / 来源外的行整行摘要一字不变；另一天的分区不受影响；冷块摘要不变；
  `detail.swapped` 记下 day 与四个计数，`status` 仍是 `verified`；被移出事件的 `temporal_matches`
  按 retire 的同一清单清掉。
- 切换后冷层仍可读：`Locate` 逐条命中且字段与切换前的热表行逐字一致；`Query` 按时间窗返回这 4 条；
  `/api/events` 返回热表 3 条 + 冷层 4 条，覆盖度头是 `chunks=2;matched=4;truncated=0`。
- `Restore`：还原 4 条后这一天 7 行的整行摘要与切换前**逐字一致**、冷块摘要不变；
  第二次 `Restore` 返回 0（幂等）。
- 拒绝条件四条各一个用例：run 未 `verified`、`day` 超出 run 范围、该日无独立日分区（行在默认分区）、
  `Archived=0`；每个都断言「报错 + 该日整行摘要不变 + 没有残留暂存表 + 不写 `detail.swapped`」。
- 计数不符时中止：直接调 `RewriteDay`，`keepSelect` 指向另一天的分区 → 报「保留计数不符」，
  返回 0/0，原分区完好；非 `SELECT`、带分号、带写语句的 `keepSelect` 一律拒绝；
  只保留部分行（2 条）是正常路径，`kept=2 / dropped=5`。
- 故障注入三种：暂存表名被占（`CREATE TABLE` 失败）、视图依赖日分区（`DETACH` 之后 `DROP TABLE` 失败，
  故障点落在事务最深处）、context 已取消；三种情况都断言原分区整行摘要不变、没有暂存表、
  能继续读写，并在排除故障后用同一个 run 正常完成切换。
- `Swap` + `Restore` 前后 `alerts` 与 4 张 `temporal_*` / `identity_observations` 的计数完全不变。
- 命令行实跑（测试库）：`ensure-schema` → 造 7 行（含 pin 与类别外/来源外）→ `shadow` → `verify` →
  `plan`（该日还没有日分区时如实拒绝并要求先 `EnsureDays`）→ `EnsureDays` 后 `plan` 报 7 = 4 + 1 + 2 →
  `swap`（不带 `-confirm` 拒绝，退出码非零）→ `swap -confirm` 移出 4 条 → `locate` 命中 →
  `Query` 4 条 / `/api/events` 7 条 → `restore -confirm` 还原 4 条 → 再 `restore` 插入 0 条。

重传判重接线（`archive_test.go` / `archive_integration_test.go`）：

- 单元（无 DB，假实现计数）：近期事件只查一次边界、`Archived` **调用 0 次**；时间恰好等于边界的事件
  仍在闸门内并查冷层；空归档不发 `Archived`；冷层命中 → `true`、未命中 → `false`；
  `Archived` 报错与边界读不到都 fail-open（返回 false）并各自计数；`Archive=nil` 完全不查、不计数；
  边界缓存 60 秒内 60 次调用只查一次库、过期后重查并立即生效；调用方 ctx 取消不写缓存；
  日志限流同一原因每分钟一条、键数有上限。
- 集成（真 `eventarchive` + 真 `Processor`）：
  - 边界：空归档 `ok=false`；`shadow` 后 `ok=true` 且等于归档事件的 `ts`。
  - **时间闸门**：近期事件入库并照常产 1 条告警，`Archived` 调用次数 **0**，边界只查 1 次。
  - **切走后重放**（同 `Envelope`、同 ID、同 ts，规则在切换后才上线）：重放 3 次都 `events` 无行、
    `alerts` 仍 0，指标上判为重复（`duplicate=true`、`alerts=0`，即 `stored=false`）；
    `Archived` 3 次、边界 1 次（缓存生效）。
  - **旧事件但冷层没有**（时间在边界内、从未归档）：`Archived` 返回 false → 照常入库并产出 1 条告警。
  - **反例**：同一重放、`Processor.Archive=nil` → 重新入库且真的新增 1 条告警（证明上一条不是规则没命中）。
  - `Restore` 之后重放：原有 `ON CONFLICT` 判重与归档闸门两条路径都不重复入库、不产告警（事件仍 1 行）。
  - `Archived` 报错：fail-open 入库 + 继续检测出 1 条告警，`ArchiveFailOpen("lookup")` 计数 1。
- 变异检查：临时去掉 `store` 里对 `archivedBefore` 的调用，上面两条关键用例立刻失败
  （「重放不该重新入库」「边界只查一次」），确认断言能真正失败。

## 12. 已知限制与后续

- **事件不删、分区不动**：阶段 A 只证明「能正确编码与对拍」，不释放任何空间。
- **超大事件（> 4 MiB）不归档**：记在 `detail.oversized` 里。这类事件会让 `Swap` 拒绝执行
  （冷块条数少于待移出条数），要么先把这一天的超大事件单独处理，要么这一天暂时不切。
- **阶段 C 只在测试库验证过**：没有在生产规模上跑过；切换是分区 DDL（父表排他锁的窗口在
  `DETACH`/`ATTACH` 期间），需要低峰窗口、需要先 `verify`，且当天应没有迟到写入。
- **`Plan` 与 `Swap` 之间仍有毫秒级窗口**：`Swap` 在自己的事务里用同一个 `keepSelect` 重新计数，
  并把 `kept/dropped` 与计划比对；但如果恰好在这几毫秒里有新事件写进该日分区，计数会不符，
  `Swap` 会写一条带 `note` 的 `detail.swapped` 并报错——此时分区已按实际口径切换，需要重跑
  `verify` 核对。要做到零窗口，得把冷热对齐检查搬进 `RewriteDay` 的事务里，本阶段没做。
- **`Restore` 逐事件调 `Materialize`**：每条都要走一次 `Locate`（扫一遍块元数据），
  还原一整天的开销与块数 × 事件数相关；只适合回滚一天，不适合天天跑。
- **`Swap` 不判断该日是否还有写入**：它只按 `verified` + 计数相等把关，没有「这天已经不再被写」
  的显式检查（例如 `ts` 上界早于某个水位）。`RetireGuard` 那种时序证据保护也没有复用。
- **同一范围可以重复跑**，每次一个新 `run_id`，冷块会叠加。去重/覆盖不在阶段 A 内，
  由运维按范围管理；阶段 C 之前应能按 run 回收（删 `event_archive_chunks` 里该 run 的行即可）。
- **对拍要求候选集不变**：构建期间大量写入时对拍会失败，这是设计上的如实报告，
  应在低峰期跑，或用较老的日期区间。
- **读取默认关闭**：`EVENT_ARCHIVE_READ=1` 才接上，且只是读取层——生产归档仍由 CLI 跑，
  没有评测过线上默认开启的开销。
- **重传判重默认关闭，且必须手工与 `swap` 对齐**：`EVENT_ARCHIVE_DEDUP=1` 才接上；用了 `swap`
  却没开它，重放会重新入库并重复告警（CLI 会提醒，但读不到 server 环境变量）。
- **判重 fail-open**：冷层故障（块损坏、`ErrChunkBudget`、库不可用）时照常入库并继续检测——
  宁可多一条可能重复的告警，也不把「无法确认」当成「已归档」永久丢事件。
  `openxdr_archive_dedup_failopen_total{stage}` 大于 0 就说明这段时间的判重不可靠，得先修冷层。
- **边界缓存 60 秒**：各节点独立缓存；切换/新归档后最多 60 秒内，这段时间的重放仍可能被判成新事件。
  另外边界变化依赖 `event_archive_chunks` 的写入，按 run 删块（回收旧归档）会让边界回退，
  这也落在缓存滞后的窗口里。
- **判重只覆盖「时间不晚于边界」的事件**：边界取自 `max(last_ts)`，事件时间晚于它时不查冷层。
  冷块里的事件时间都不会晚于边界，所以这是精确的前置条件，不是近似。
- **判重与检测的顺序**：判定发生在 `store` 里、这条事件的 `INSERT` 之前——此刻事务还没有为
  这条事件写过任何东西，命中冷层就直接返回（不产告警、不写时序命中、不写身份观测），
  没有需要回滚的副作用。
  冷层查询走连接池（`eventarchive` 的只读函数），不借用事务连接，所以一次慢查询不会把事务
  变成「持锁等待」；代价是这些罕见事件会短时多占一个连接。
- **没有跨节点的边界一致性**：每个 server 节点各自缓存，`swap` 之后各节点的窗口彼此独立；
  多节点部署时按最慢的缓存周期理解这段滞后。
- **关键词不进冷层**：冷块没有关键词索引，带 `q` 的查询只查热表，用 `X-Archive-Coverage: skipped=keyword` 说明。
- **冷查询有时间边界差**：热表含 `ts <= to`，冷块是 `[from, to)`；接口给冷查询补了 1ns，直接调
  `eventarchive.Query` 的调用方要自己处理这个边界。
- **没有跨 run 的覆盖度统计**：查询只说「这次扫了几块、命中几条、是否被预算/上限截断」。
  某段时间到底有没有被完整归档，仍需按 run 的 `detail` 与对拍结果判断（B2 生命周期里还没做）。
- **审计与限流没有跟进**：冷读没有单独的审计事件，也没有按调用方的配额；两者都要在真正扩大使用范围
  之前定下来。
- **按 ID 定位要先扫一遍块元数据**：Bloom 在 Go 侧判断，SQL 只能按 `(first_ts, last_ts, id)` 排序
  取元数据（每块一行，含 `id_bloom` 的堆访问），不碰 payload。归档块数很大时这一步是线性的，
  阶段 C 若要按 ID 高频判重，应改用「按天分桶 + 时间窗提示」或把 filter 收缩到更小的元数据表。
- **超预算只报错，不自动分批**：`ErrChunkBudget` 之后的动作留给调用方（缩小日期范围，或在阶段 C
  调高/更换预算口径），本阶段不擅自放宽上限。
- **物化还没有审计、权限与 API**：`Materialize` 是库函数加 CLI，直接连库执行，没有审计事件、
  没有 RBAC 判断；接进 API 时必须补审计（谁在什么时候把哪条冷事件物化成了证据）与组权限。
- **重传判重已接线但默认关闭**：见第 9 节「重传判重接线」；`EVENT_ARCHIVE_DEDUP=1` 才生效，
  且每次判重要扫一遍块元数据（见上一条），所以只对「时间不晚于边界」的罕见重传开放。
  接入面目前只用到 `Exists` 与 `Boundary`，`Locate` / `Materialize` 仍是库函数 + CLI。
- **同一条事件被多轮 run 归档时**，`Locate` 返回最新一块里的副本，不比较副本之间的差异；
  每个 run 的副本一致性由该 run 的对拍（`verify`）负责。
- **`report` 要解码全部冷块**：为了按 id 回查 events 的整行字节，它逐块解码取 id（顺带又校验了一遍
  块完整性），耗时与归档条数成正比；大 run 上先在低峰期跑。
