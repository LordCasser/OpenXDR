// Package queryrole 为每个组开通 Pi query 工具用的只读数据库身份。
//
// 每组一个 schema 加一个登录角色：schema 里是写死组过滤的 security_barrier 视图，
// 角色只能读这些视图，读不到任何业务基表（agentchat/query.go 每次查询前还会再校验）。
// 组过滤必须固化在视图定义里而不是会话变量——模型写的 SQL 能改会话变量。
//
// 开通需要平台账号有 CREATEROLE（或超级用户）。没有就不开通，记一次日志，
// 退回 deploy/pi-query/group-views.sql 的手工流程；PI_QUERY_DATABASE_URLS 里
// 手工配置的身份始终优先。
package queryrole

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entgroup "openxdr/server/ent/group"
)

type Provisioner struct {
	// 平台连接，用来建视图与角色
	DB     *sql.DB
	Client *ent.Client
	// 平台 DSN（URL 形式），换掉账号密码就是组查询 DSN
	BaseDSN string
	// PI_QUERY_DATABASE_URLS 手工开通的身份
	Static map[uuid.UUID]string
}

// names 组的 schema 与角色名。取 UUID 末 12 位（v7 的随机段），只含十六进制，可直接拼进 DDL。
func names(group uuid.UUID) (schema, role string) {
	hex := strings.ReplaceAll(group.String(), "-", "")
	schema = "xdr_g_" + hex[20:]
	return schema, schema + "_ro"
}

// URL 组的只读查询 DSN，未开通返回空。
func (p *Provisioner) URL(ctx context.Context, group uuid.UUID) string {
	if dsn := p.Static[group]; dsn != "" {
		return dsn
	}
	g, err := p.Client.Group.Query().Where(entgroup.IDEQ(group)).Select(entgroup.FieldQueryPassword).Only(ctx)
	if err != nil || g.QueryPassword == "" {
		return ""
	}
	u, err := url.Parse(p.BaseDSN)
	if err != nil || u.Scheme == "" {
		return ""
	}
	_, role := names(group)
	u.User = url.UserPassword(role, g.QueryPassword)
	return u.String()
}

// Allowed 平台账号能否建角色。
func (p *Provisioner) Allowed(ctx context.Context) (bool, error) {
	var ok bool
	err := p.DB.QueryRowContext(ctx, `SELECT rolsuper OR rolcreaterole FROM pg_roles WHERE rolname = current_user`).Scan(&ok)
	return ok, err
}

// Reconcile 启动时补齐：给所有未手工配置的组开通或刷新视图。刷新让视图定义随版本升级。
func (p *Provisioner) Reconcile(ctx context.Context) {
	ok, err := p.Allowed(ctx)
	if err != nil {
		slog.Error("检查查询身份开通权限失败", "err", err)
		return
	}
	if !ok {
		slog.Warn("平台数据库账号没有 CREATEROLE，组查询身份需按 deploy/pi-query/group-views.sql 手工开通")
		return
	}
	groups, err := p.Client.Group.Query().IDs(ctx)
	if err != nil {
		slog.Error("列出组失败", "err", err)
		return
	}
	for _, id := range groups {
		if p.Static[id] != "" {
			continue
		}
		if err := p.Ensure(ctx, id); err != nil {
			slog.Error("开通组查询身份失败", "group", id, "err", err)
		}
	}
}

// ErrNotAllowed 平台账号没有建角色的权限，只能手工开通。
var ErrNotAllowed = errors.New("平台数据库账号没有 CREATEROLE")

// Ensure 建或刷新组的视图与角色；首次开通生成密码存到组上。可重复执行，集群内多节点并发也安全。
func (p *Provisioner) Ensure(ctx context.Context, group uuid.UUID) error {
	if p.Static[group] != "" {
		return nil
	}
	if ok, err := p.Allowed(ctx); err != nil || !ok {
		if err == nil {
			err = ErrNotAllowed
		}
		return err
	}
	tx, err := p.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// 角色是集群级对象，并发 CREATE ROLE 会撞；同一把事务锁串行化所有开通
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('openxdr:queryrole'))`); err != nil {
		return err
	}
	var password string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(query_password, '') FROM groups WHERE id = $1`, group).Scan(&password); err != nil {
		return err
	}
	fresh := password == ""
	if fresh {
		if password, err = randomPassword(); err != nil {
			return err
		}
	}
	for i, stmt := range ddl(group, password, fresh) {
		// 不把语句带进错误：最后一条含密码
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("开通第 %d 步失败：%w", i+1, err)
		}
	}
	if fresh {
		if _, err := tx.ExecContext(ctx, `UPDATE groups SET query_password = $1 WHERE id = $2`, password, group); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Drop 删组时回收视图与角色，别留一个还能登录的账号。
func (p *Provisioner) Drop(ctx context.Context, group uuid.UUID) error {
	if p.Static[group] != "" {
		return nil
	}
	schema, role := names(group)
	tx, err := p.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('openxdr:queryrole'))`); err != nil {
		return err
	}
	for _, stmt := range []string{
		fmt.Sprintf(`DROP SCHEMA IF EXISTS %s CASCADE`, schema),
		fmt.Sprintf(`DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%[1]s') THEN
  EXECUTE format('REVOKE ALL ON DATABASE %%I FROM %[1]s', current_database());
  DROP ROLE %[1]s;
END IF; END $$`, role),
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ddl 与 deploy/pi-query/group-views.sql 同一口径，改视图时两边一起改。
func ddl(group uuid.UUID, password string, fresh bool) []string {
	schema, role := names(group)
	gid := "'" + group.String() + "'"
	inGroup := "asset_id IN (SELECT id FROM public.assets WHERE group_id = " + gid + ")"
	stmts := []string{
		`CREATE SCHEMA IF NOT EXISTS ` + schema,
		// 新列只能加在末尾：CREATE OR REPLACE VIEW 不允许改已有列的顺序
		`CREATE OR REPLACE VIEW ` + schema + `.assets WITH (security_barrier) AS
  SELECT id, hostname, os, ip_addrs, agent_id, first_seen, last_seen,
         agent_version, silent_since, role, criticality, summary, listening, cloud,
         service_notes, egress_notes, zone_id, inventory_at
  FROM public.assets WHERE group_id = ` + gid,
		`CREATE OR REPLACE VIEW ` + schema + `.findings WITH (security_barrier) AS
  SELECT id, asset_id, key, title, detail, severity, status, first_seen, last_seen, resolved_at, resolved_by, note
  FROM public.findings WHERE group_id = ` + gid,
		// 只含本组主机上的抑制；全局抑制只有平台 admin 看得到
		`CREATE OR REPLACE VIEW ` + schema + `.suppressions WITH (security_barrier) AS
  SELECT id, created_at, rule_id, asset_id, reason, created_by, expires_at, matched_count, last_matched_at,
         status, conditions, reviewed_by, reviewed_at
  FROM public.suppressions WHERE ` + inGroup,
		`CREATE OR REPLACE VIEW ` + schema + `.memories WITH (security_barrier) AS
  SELECT id, created_at, updated_at, asset_id, content, source, author
  FROM public.memories WHERE group_id = ` + gid,
		`CREATE OR REPLACE VIEW ` + schema + `.asset_links WITH (security_barrier) AS
  SELECT src_ip, src_asset_id, dst_ip, dst_port, proto, process, count, first_seen, last_seen
  FROM public.asset_links WHERE src_asset_id IN (SELECT id FROM public.assets WHERE group_id = ` + gid + `)`,
		// 只给本组主机连过的地址，别组的外联目的不外泄
		`CREATE OR REPLACE VIEW ` + schema + `.ip_infos WITH (security_barrier) AS
  SELECT ip, ptr, as_owner, asn, country, malicious, suspicious, domains, vt_at
  FROM public.ip_infos WHERE ip IN (SELECT dst_ip FROM public.asset_links
    WHERE src_asset_id IN (SELECT id FROM public.assets WHERE group_id = ` + gid + `))`,
		`CREATE OR REPLACE VIEW ` + schema + `.reports WITH (security_barrier) AS
  SELECT id, created_at, title, level, markdown
  FROM public.reports WHERE group_id = ` + gid,
		`CREATE OR REPLACE VIEW ` + schema + `.events WITH (security_barrier) AS
  SELECT id, ts, class_uid, source, asset_id, username, conn_tuple, raw
  FROM public.events WHERE ` + inGroup,
		`CREATE OR REPLACE VIEW ` + schema + `.alerts WITH (security_barrier) AS
  SELECT id, ts, last_ts, count, rule_id, severity, event_id, asset_id, incident_id, command_id, detail
  FROM public.alerts WHERE ` + inGroup,
		// 告警连同它的原始事件：在视图里按主键回查，跨视图 JOIN events 会全表扫描、必然超时
		`CREATE OR REPLACE VIEW ` + schema + `.alert_events WITH (security_barrier) AS
  SELECT a.id AS alert_id, a.ts, a.last_ts, a.count, a.rule_id, a.severity, a.asset_id, a.incident_id, a.command_id,
         e.id AS event_id, e.ts AS event_ts, e.class_uid, e.username, e.conn_tuple, e.raw
  FROM public.alerts a JOIN public.events e ON e.id = a.event_id AND e.asset_id = a.asset_id
  WHERE a.` + inGroup,
		`CREATE OR REPLACE VIEW ` + schema + `.incidents WITH (security_barrier) AS
  SELECT i.id, i.created_at, i.status, i.title, i.ai_verdict, i.graph
  FROM public.incidents i
  WHERE EXISTS (SELECT 1 FROM public.alerts a WHERE a.incident_id = i.id)
    AND NOT EXISTS (
      SELECT 1 FROM public.alerts a
      WHERE a.incident_id = i.id
        AND (a.asset_id IS NULL OR a.asset_id NOT IN
             (SELECT id FROM public.assets WHERE group_id = ` + gid + `)))`,
		// 旧版视图带已删除的列，CREATE OR REPLACE 删不掉列，先整个删掉；授权由下面的 GRANT ON ALL TABLES 补回
		`DROP VIEW IF EXISTS ` + schema + `.commands`,
		`CREATE VIEW ` + schema + `.commands WITH (security_barrier) AS
  SELECT id, created_at, completed_at, kind, status, asset_id, incident_id,
         issued_by, detail, cmd, exit_code, stdout, stderr, truncated
  FROM public.commands WHERE ` + inGroup,
		`COMMENT ON SCHEMA ` + schema + ` IS 'OpenXDR 单组只读视图，供 Pi query 工具使用'`,
		`COMMENT ON VIEW ` + schema + `.events IS '本组原始事件（OCSF 风格，raw 为 JSON）；查询务必带 ts 范围'`,
		`COMMENT ON VIEW ` + schema + `.alerts IS '本组告警（去重后，count 为累计次数）'`,
		`COMMENT ON VIEW ` + schema + `.alert_events IS '本组告警连同触发它的原始事件（event_ts、class_uid、raw）；按 incident_id、rule_id、alert_id 过滤'`,
		`COMMENT ON VIEW ` + schema + `.incidents IS '本组 incident（全部告警都在本组）'`,
		`COMMENT ON VIEW ` + schema + `.findings IS '本组运维待办（track 登记的问题，status 为 open / resolved / ignored）'`,
		`COMMENT ON VIEW ` + schema + `.suppressions IS '本组主机上的抑制规则（status：active 生效 / proposed 待批 / rejected 已拒绝）'`,
		`COMMENT ON VIEW ` + schema + `.memories IS '本组长期记忆（source：human 人工 / ai）'`,
		`COMMENT ON VIEW ` + schema + `.asset_links IS '本组主机发起的连接聚合成的依赖边'`,
		`COMMENT ON VIEW ` + schema + `.ip_infos IS '本组主机连过的公网地址：反向解析与 VirusTotal 结果'`,
		`COMMENT ON VIEW ` + schema + `.reports IS '本组历史报告（level：ok / attention / urgent）'`,
		`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '` + role + `') THEN CREATE ROLE ` + role + ` LOGIN; END IF; END $$`,
		`ALTER ROLE ` + role + ` WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 5`,
		`ALTER ROLE ` + role + ` SET search_path = ` + schema,
		`ALTER ROLE ` + role + ` SET default_transaction_read_only = on`,
		`ALTER ROLE ` + role + ` SET statement_timeout = '5s'`,
		`DO $$ BEGIN EXECUTE format('GRANT CONNECT ON DATABASE %I TO ` + role + `', current_database()); END $$`,
		`GRANT USAGE ON SCHEMA ` + schema + ` TO ` + role,
		`GRANT SELECT ON ALL TABLES IN SCHEMA ` + schema + ` TO ` + role,
	}
	if fresh {
		// 密码只含 URL-safe base64 字符，没有引号
		stmts = append(stmts, `ALTER ROLE `+role+` PASSWORD '`+password+`'`)
	}
	return stmts
}

// DropDryRun 删除演练模式遗留的 dry_run 列（列留着会默默记成 true），可重复执行。
// 旧版组视图引用 commands.dry_run，必须在 Reconcile 重建视图之后调用。
// 列已不存在就不碰表，免得每次启动都抢一次排他锁。
func DropDryRun(ctx context.Context, db *sql.DB) error {
	var errs []error
	for _, table := range []string{"commands", "agent_sessions", "approvals", "tasks"} {
		if err := dropColumn(ctx, db, table, "dry_run"); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", table, err))
		}
	}
	return errors.Join(errs...)
}

func dropColumn(ctx context.Context, db *sql.DB, table, column string) error {
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
  WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2)`, table, column).Scan(&exists); err != nil || !exists {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// 排队等排他锁会堵住这张表的所有读写，等不到就放弃，下次启动再删
	if _, err := tx.ExecContext(ctx, `SET LOCAL lock_timeout = '5s'`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE `+table+` DROP COLUMN IF EXISTS `+column); err != nil {
		return err
	}
	return tx.Commit()
}

func randomPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
