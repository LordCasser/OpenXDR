package identity

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// 增量游标的回看窗口。入库事务的 recorded_at 取事务开始时间，提交顺序与它不一致，
// 每轮回看 10 分钟重做一遍；各步骤幂等，重复处理不改变结果。
const graphOverlap = 10 * time.Minute

// NormName 是候选匹配用的名字归一化：去掉 DOMAIN\ 前缀与 @后缀再转小写。
// 与 identity_accounts_name 索引表达式必须逐字一致，否则用不上索引。
const NormName = `lower(regexp_replace(%s,'^.*\\|@.*$','','g'))`

// RunGraph 由 cluster.RunLeader 托管，每分钟增量更新一次身份图。
func RunGraph(ctx context.Context, db *sql.DB) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for ctx.Err() == nil {
		workCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		groups, err := SyncGraph(workCtx, db)
		cancel()
		if err != nil {
			slog.Warn("身份图更新未完成，下轮重试", "err", err)
		} else if groups > 0 {
			slog.Info("身份图已更新", "groups", groups)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// SyncGraph 一轮增量更新：登记新出现的账号、关联 Linux 登录与当时的清单、重算有变化的组的链接。
// 任一步失败都不前移游标，下一轮整轮重做。返回重算的组数。
func SyncGraph(ctx context.Context, db *sql.DB) (int, error) {
	var upper time.Time
	if err := db.QueryRowContext(ctx, `SELECT now()`).Scan(&upper); err != nil {
		return 0, err
	}
	cursors := map[string]time.Time{}
	rows, err := db.QueryContext(ctx, `SELECT name,at FROM identity_graph_cursors`)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var name string
		var at time.Time
		if err := rows.Scan(&name, &at); err != nil {
			rows.Close()
			return 0, err
		}
		cursors[name] = at
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	since := func(name string) time.Time {
		at, ok := cursors[name]
		if !ok {
			return time.Time{}
		}
		return at.Add(-graphOverlap)
	}
	// 滚动升级期间旧节点写入的快照没有 ts，先按原事件补齐
	if _, err := db.ExecContext(ctx, `UPDATE identity_local_snapshots s SET ts=e.ts FROM events e WHERE s.ts IS NULL AND e.id=s.event_id`); err != nil {
		return 0, err
	}
	dirty := map[uuid.UUID]bool{}
	for _, step := range []struct {
		query string
		args  []any
	}{
		{discoverDirectory, []any{since("directory")}},
		{discoverWindows, []any{since("observations")}},
		{discoverLinux, []any{since("snapshots")}},
		{dirtyGroups, nil},
	} {
		if err := collectGroups(ctx, db, dirty, step.query, step.args...); err != nil {
			return 0, err
		}
	}
	_, rematch := cursors["snapshots"]
	if _, err := db.ExecContext(ctx, matchLinuxLogins, since("observations"), since("snapshots"), rematch); err != nil {
		return 0, err
	}
	for group := range dirty {
		if err := reconcile(ctx, db, group); err != nil {
			return 0, err
		}
	}
	_, err = db.ExecContext(ctx, `INSERT INTO identity_graph_cursors(name,at) SELECT unnest(ARRAY['directory','observations','snapshots']),$1
 ON CONFLICT(name) DO UPDATE SET at=EXCLUDED.at`, upper)
	return len(dirty), err
}

func collectGroups(ctx context.Context, db *sql.DB, into map[uuid.UUID]bool, query string, args ...any) error {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var group uuid.UUID
		if err := rows.Scan(&group); err != nil {
			return err
		}
		into[group] = true
	}
	return rows.Err()
}

func reconcile(ctx context.Context, db *sql.DB, group uuid.UUID) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := ReconcileGroup(ctx, tx, group); err != nil {
		return err
	}
	return tx.Commit()
}

// LockGroup 串行化同组的后台重算与人工确认/拒绝/撤销，避免两边交错写出互相矛盾的链接。
func LockGroup(ctx context.Context, tx *sql.Tx, group uuid.UUID) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('openxdr:identity-graph:'||$1::text,0))`, group)
	return err
}

// ReconcileGroup 按强证据重算组内每个账号的默认归属，幂等，只在有差异时写入：
//   - 目录账号是身份锚点，每个目录账号一个身份；
//   - Windows 账号 SID 恰好等于组内一个 AD 账号的 objectSid 时链接到该目录身份，多个则视为歧义不链接；
//   - 其余账号各自是「主机内身份」，不跨主机合并。
//
// 人工确认的链接不被后台改写；账号或身份锚点所在资产已离开本组时，链接（含人工）一律撤销。
func ReconcileGroup(ctx context.Context, tx *sql.Tx, group uuid.UUID) error {
	if err := LockGroup(ctx, tx, group); err != nil {
		return err
	}
	for _, stmt := range []string{reconcileRevokeOutOfGroup, reconcileIdentities, reconcileRevokeChanged, reconcileInsertLinks} {
		if _, err := tx.ExecContext(ctx, stmt, group); err != nil {
			return err
		}
	}
	return nil
}

// 目录账号：每次同步都会刷新 observed_at，SID 变化随之进入重算。
const discoverDirectory = `WITH up AS (
INSERT INTO identity_accounts AS t (group_id,kind,account_key,directory_account_id,sid,name,first_seen,last_seen)
SELECT s.group_id,'directory','directory:'||a.id,a.id,a.windows_sid,a.username,a.observed_at,a.observed_at
FROM identity_directory_accounts a JOIN identity_directory_sources s ON s.id=a.source_id
WHERE a.observed_at>$1
ON CONFLICT(group_id,account_key) DO UPDATE SET sid=EXCLUDED.sid,name=EXCLUDED.name,last_seen=GREATEST(t.last_seen,EXCLUDED.last_seen)
WHERE (t.sid,t.name) IS DISTINCT FROM (EXCLUDED.sid,EXCLUDED.name) OR t.last_seen<EXCLUDED.last_seen
RETURNING t.group_id) SELECT DISTINCT group_id FROM up`

// Windows 账号：沿用观察里的 (组, 资产, SID) 账号键；未归组、组已删除或缺 SID 的观察不登记。
const discoverWindows = `WITH up AS (
INSERT INTO identity_accounts AS t (group_id,kind,account_key,asset_id,sid,name,domain,first_seen,last_seen)
SELECT o.group_id,'windows',o.account_key,o.asset_id,o.account_sid,
 (array_agg(o.account_name ORDER BY e.ts DESC,o.event_id DESC) FILTER (WHERE o.account_name IS NOT NULL))[1],
 (array_agg(o.account_domain ORDER BY e.ts DESC,o.event_id DESC) FILTER (WHERE o.account_domain IS NOT NULL))[1],
 min(e.ts),max(e.ts)
FROM identity_observations o JOIN events e ON e.id=o.event_id JOIN groups g ON g.id=o.group_id
WHERE o.recorded_at>$1 AND o.state='observed' AND o.account_key IS NOT NULL AND o.account_sid IS NOT NULL
GROUP BY o.group_id,o.account_key,o.asset_id,o.account_sid
ON CONFLICT(group_id,account_key) DO UPDATE SET
 name=CASE WHEN EXCLUDED.last_seen>=t.last_seen THEN COALESCE(EXCLUDED.name,t.name) ELSE t.name END,
 domain=CASE WHEN EXCLUDED.last_seen>=t.last_seen THEN COALESCE(EXCLUDED.domain,t.domain) ELSE t.domain END,
 first_seen=LEAST(t.first_seen,EXCLUDED.first_seen),last_seen=GREATEST(t.last_seen,EXCLUDED.last_seen)
WHERE EXCLUDED.first_seen<t.first_seen OR EXCLUDED.last_seen>t.last_seen
 OR (EXCLUDED.last_seen=t.last_seen AND (EXCLUDED.name,EXCLUDED.domain) IS DISTINCT FROM (t.name,t.domain))
RETURNING t.group_id) SELECT DISTINCT group_id FROM up`

// Linux 账号：键为 (组, 资产, UID, 用户名)。同名不同 UID 是不同账号（可能删了重建），不合并。
const discoverLinux = `WITH up AS (
INSERT INTO identity_accounts AS t (group_id,kind,account_key,asset_id,uid,name,first_seen,last_seen)
SELECT s.group_id,'linux','linux-local:'||s.group_id||':'||s.asset_id||':'||a.uid||':'||a.name,s.asset_id,a.uid,a.name,min(s.ts),max(s.ts)
FROM identity_local_snapshots s JOIN identity_local_accounts a ON a.event_id=s.event_id JOIN groups g ON g.id=s.group_id
WHERE s.recorded_at>$1 AND s.state='observed' AND s.ts IS NOT NULL
GROUP BY s.group_id,s.asset_id,a.uid,a.name
ON CONFLICT(group_id,account_key) DO UPDATE SET first_seen=LEAST(t.first_seen,EXCLUDED.first_seen),last_seen=GREATEST(t.last_seen,EXCLUDED.last_seen)
WHERE EXCLUDED.first_seen<t.first_seen OR EXCLUDED.last_seen>t.last_seen
RETURNING t.group_id) SELECT DISTINCT group_id FROM up`

// 需要重算的其他组：有账号还没归属，或有链接的账号/身份锚点所在资产已离开本组。
const dirtyGroups = `SELECT a.group_id FROM identity_accounts a LEFT JOIN assets s ON s.id=a.asset_id
WHERE (a.asset_id IS NULL OR s.group_id=a.group_id)
 AND NOT EXISTS(SELECT 1 FROM identity_links l WHERE l.account_id=a.id AND l.revoked_at IS NULL)
UNION
SELECT l.group_id FROM identity_links l JOIN identities i ON i.id=l.identity_id
 JOIN identity_accounts a ON a.id=l.account_id LEFT JOIN assets s ON s.id=a.asset_id
 JOIN identity_accounts anchor ON anchor.id=i.anchor_account_id LEFT JOIN assets anchor_asset ON anchor_asset.id=anchor.asset_id
WHERE l.revoked_at IS NULL AND ((a.asset_id IS NOT NULL AND s.group_id IS DISTINCT FROM a.group_id)
 OR (anchor.asset_id IS NOT NULL AND anchor_asset.group_id IS DISTINCT FROM anchor.group_id))`

// Linux 登录关联当时有效的清单：同资产、同历史组、登录时刻及之前 24 小时内最新的一份快照。
// 该快照不可用就标 snapshot_unavailable，不往前找更旧的；快照里没有同名账号标 no_account；
// 窗口内没有快照标 no_snapshot。迟到的快照会让窗口内已关联的登录重算一次。
const matchLinuxLogins = `WITH targets AS (
 SELECT o.event_id FROM identity_observations o WHERE o.recorded_at>$1 AND o.state='missing_uid'
 UNION
 SELECT m.event_id FROM identity_local_snapshots s JOIN identity_login_matches m
  ON m.asset_id=s.asset_id AND m.group_id=s.group_id AND m.ts>=s.ts AND m.ts<=s.ts+interval '24 hours'
 WHERE $3 AND s.recorded_at>$2 AND s.ts IS NOT NULL
), computed AS (
 SELECT o.event_id,o.group_id,o.asset_id,e.ts,o.account_name,o.success,
  NULLIF(left(e.raw->'src_endpoint'->>'ip',256),'') AS address,
  snap.event_id AS snap_id,snap.state AS snap_state,snap.ts AS snap_ts,acct.uid
 FROM targets t JOIN identity_observations o ON o.event_id=t.event_id JOIN events e ON e.id=o.event_id
 JOIN groups g ON g.id=o.group_id
 LEFT JOIN LATERAL (SELECT s.event_id,s.state,s.ts FROM identity_local_snapshots s
  WHERE s.asset_id=o.asset_id AND s.group_id=o.group_id AND s.ts<=e.ts AND s.ts>=e.ts-interval '24 hours'
  ORDER BY s.ts DESC,s.event_id DESC LIMIT 1) snap ON true
 LEFT JOIN identity_local_accounts acct ON snap.state='observed' AND acct.event_id=snap.event_id AND acct.name=o.account_name
 WHERE o.state='missing_uid' AND o.account_name IS NOT NULL AND o.success IS NOT NULL
)
INSERT INTO identity_login_matches AS m (event_id,group_id,asset_id,ts,account_name,success,source_address,state,snapshot_event_id,snapshot_ts,uid)
SELECT event_id,group_id,asset_id,ts,account_name,success,address,
 CASE WHEN snap_id IS NULL THEN 'no_snapshot' WHEN snap_state<>'observed' THEN 'snapshot_unavailable'
  WHEN uid IS NULL THEN 'no_account' ELSE 'matched' END,
 snap_id,snap_ts,uid FROM computed
ON CONFLICT(event_id) DO UPDATE SET state=EXCLUDED.state,snapshot_event_id=EXCLUDED.snapshot_event_id,
 snapshot_ts=EXCLUDED.snapshot_ts,uid=EXCLUDED.uid,matched_at=clock_timestamp()
WHERE (m.state,m.snapshot_event_id,m.uid) IS DISTINCT FROM (EXCLUDED.state,EXCLUDED.snapshot_event_id,EXCLUDED.uid)`

// visibleAccounts 组内当前有效的账号：目录账号，或资产仍在本组的主机账号。
const visibleAccounts = `vis AS (SELECT a.* FROM identity_accounts a LEFT JOIN assets s ON s.id=a.asset_id
 WHERE a.group_id=$1 AND (a.asset_id IS NULL OR s.group_id=$1))`

const desiredLinks = `WITH ` + visibleAccounts + `,
sidm AS (
 SELECT w.id AS account_id,count(*) AS n,(array_agg(d.id ORDER BY d.id))[1] AS dir_account,
  (array_agg(jsonb_build_object('directoryAccountId',da.id,'sourceId',src.id,'authority',src.authority,
   'externalId',da.external_id,'objectSid',da.windows_sid,'observedAt',da.observed_at) ORDER BY d.id))[1] AS directory
 FROM vis w JOIN vis d ON d.kind='directory' AND d.sid=w.sid
 JOIN identity_directory_accounts da ON da.id=d.directory_account_id AND da.windows_sid=w.sid
 JOIN identity_directory_sources src ON src.id=da.source_id AND src.kind='ad' AND src.group_id=$1
 WHERE w.kind='windows' GROUP BY w.id
), desired AS (
 SELECT a.id AS account_id,
  CASE WHEN a.kind='windows' AND m.n=1 THEN m.dir_account ELSE a.id END AS anchor,
  CASE WHEN a.kind='directory' OR m.n=1 THEN 'directory' ELSE 'host' END AS identity_kind,
  CASE WHEN a.kind='directory' THEN 'directory_anchor' WHEN m.n=1 THEN 'ad_sid' ELSE 'host_local' END AS basis,
  CASE WHEN a.kind='directory' THEN 'authoritative' WHEN m.n=1 THEN 'strong' ELSE 'local' END AS confidence,
  CASE WHEN a.kind='directory' THEN jsonb_build_object('rule','directory_account','directoryAccountId',da.id,
    'sourceId',da.source_id,'externalId',da.external_id)
   WHEN m.n=1 THEN jsonb_build_object('rule','windows_sid_equals_ad_object_sid','assetId',a.asset_id,'sid',a.sid,'directory',m.directory)
   WHEN a.kind='windows' THEN jsonb_build_object('rule','host_scoped','assetId',a.asset_id,'sid',a.sid,'ambiguousDirectoryMatches',COALESCE(m.n,0))
   ELSE jsonb_build_object('rule','host_scoped','assetId',a.asset_id,'uid',a.uid,'name',a.name) END AS evidence
 FROM vis a LEFT JOIN sidm m ON m.account_id=a.id LEFT JOIN identity_directory_accounts da ON da.id=a.directory_account_id
)`

const reconcileRevokeOutOfGroup = `WITH ` + visibleAccounts + `,
bad AS (
 SELECT l.id,NOT EXISTS(SELECT 1 FROM vis WHERE vis.id=l.account_id) AS account_gone
 FROM identity_links l JOIN identities i ON i.id=l.identity_id
 WHERE l.group_id=$1 AND l.revoked_at IS NULL AND (NOT EXISTS(SELECT 1 FROM vis WHERE vis.id=l.account_id)
  OR NOT EXISTS(SELECT 1 FROM vis WHERE vis.id=i.anchor_account_id)))
UPDATE identity_links l SET revoked_at=clock_timestamp(),revoked_by='system',
 revoke_reason=CASE WHEN bad.account_gone THEN 'account_out_of_group' ELSE 'anchor_out_of_group' END
FROM bad WHERE l.id=bad.id`

// 已有人工链接的账号不再需要默认身份，避免给它们造空身份
const reconcileIdentities = desiredLinks + `
INSERT INTO identities(group_id,kind,anchor_account_id)
SELECT DISTINCT $1::uuid,d.identity_kind,d.anchor FROM desired d
WHERE NOT EXISTS(SELECT 1 FROM identity_links l WHERE l.account_id=d.account_id AND l.revoked_at IS NULL AND l.basis='manual')
ON CONFLICT(anchor_account_id) DO NOTHING`

const reconcileRevokeChanged = desiredLinks + `
UPDATE identity_links l SET revoked_at=clock_timestamp(),revoked_by='system',revoke_reason='evidence_changed'
FROM desired d JOIN identities i ON i.anchor_account_id=d.anchor
WHERE l.account_id=d.account_id AND l.revoked_at IS NULL AND l.basis<>'manual' AND (l.identity_id<>i.id OR l.basis<>d.basis)`

const reconcileInsertLinks = desiredLinks + `
INSERT INTO identity_links(group_id,identity_id,account_id,basis,confidence,evidence,source)
SELECT $1,i.id,d.account_id,d.basis,d.confidence,d.evidence,'system'
FROM desired d JOIN identities i ON i.anchor_account_id=d.anchor
WHERE NOT EXISTS(SELECT 1 FROM identity_links l WHERE l.account_id=d.account_id AND l.revoked_at IS NULL)`
