-- 为一个组建立 Pi query 工具专用的只读视图与登录角色（手工开通）。
-- 平台数据库账号有 CREATEROLE 时 server 会自动开通，不需要这个脚本；
-- 视图定义与 server/internal/queryrole 同一口径，改一边须同步另一边。
-- 组过滤写死在视图定义里，角色只能读本 schema 的视图、读不到任何业务基表
-- （server/internal/agentchat/query.go 会逐项校验，不满足就拒绝查询）。
--
-- 用法（数据库超级用户，在 Patroni leader 上执行，可重复执行）：
--   psql -v ON_ERROR_STOP=1 -v group_id=<组 UUID> -v schema=xdr_<短名> \
--        -v role=xdr_<短名>_ro -v password=<URL-safe 随机串> -f group-views.sql
-- 然后把 postgres://<role>:<password>@127.0.0.1:15432/openxdr?sslmode=disable
-- 写进 PI_QUERY_DATABASE_URLS（JSON：组 UUID → DSN），重启 server。

BEGIN;

CREATE SCHEMA IF NOT EXISTS :"schema";

-- 本组资产
-- 新列只能加在末尾：CREATE OR REPLACE VIEW 不允许改已有列的顺序
CREATE OR REPLACE VIEW :"schema".assets WITH (security_barrier) AS
  SELECT id, hostname, os, ip_addrs, agent_id, first_seen, last_seen,
         agent_version, silent_since, role, criticality, summary, listening, cloud,
         service_notes, egress_notes, zone_id, inventory_at
  FROM public.assets WHERE group_id = :'group_id';

CREATE OR REPLACE VIEW :"schema".findings WITH (security_barrier) AS
  SELECT id, asset_id, key, title, detail, severity, status, first_seen, last_seen, resolved_at, resolved_by, note
  FROM public.findings WHERE group_id = :'group_id';

-- 只含本组主机上的抑制；全局抑制只有平台 admin 看得到
CREATE OR REPLACE VIEW :"schema".suppressions WITH (security_barrier) AS
  SELECT id, created_at, rule_id, asset_id, reason, created_by, expires_at, matched_count, last_matched_at,
         status, conditions, reviewed_by, reviewed_at
  FROM public.suppressions WHERE asset_id IN (SELECT id FROM public.assets WHERE group_id = :'group_id');

CREATE OR REPLACE VIEW :"schema".memories WITH (security_barrier) AS
  SELECT id, created_at, updated_at, asset_id, content, source, author
  FROM public.memories WHERE group_id = :'group_id';

CREATE OR REPLACE VIEW :"schema".asset_links WITH (security_barrier) AS
  SELECT src_ip, src_asset_id, dst_ip, dst_port, proto, process, count, first_seen, last_seen
  FROM public.asset_links WHERE src_asset_id IN (SELECT id FROM public.assets WHERE group_id = :'group_id');

-- 只给本组主机连过的地址，别组的外联目的不外泄
CREATE OR REPLACE VIEW :"schema".ip_infos WITH (security_barrier) AS
  SELECT ip, ptr, as_owner, asn, country, malicious, suspicious, domains, vt_at
  FROM public.ip_infos WHERE ip IN (SELECT dst_ip FROM public.asset_links
    WHERE src_asset_id IN (SELECT id FROM public.assets WHERE group_id = :'group_id'));

CREATE OR REPLACE VIEW :"schema".reports WITH (security_barrier) AS
  SELECT id, created_at, title, level, markdown
  FROM public.reports WHERE group_id = :'group_id';

-- 原始事件：只含本组资产，查询务必带 ts 时间范围（按 asset_id, ts 建有索引）
CREATE OR REPLACE VIEW :"schema".events WITH (security_barrier) AS
  SELECT id, ts, class_uid, source, asset_id, username, conn_tuple, raw
  FROM public.events
  WHERE asset_id IN (SELECT id FROM public.assets WHERE group_id = :'group_id');

-- 告警：只含本组资产
CREATE OR REPLACE VIEW :"schema".alerts WITH (security_barrier) AS
  SELECT id, ts, last_ts, count, rule_id, severity, event_id, asset_id, incident_id, command_id
  FROM public.alerts
  WHERE asset_id IN (SELECT id FROM public.assets WHERE group_id = :'group_id');

-- incident：与 REST 接口同一口径，全部告警都落在本组资产上才可见，跨组的不给
CREATE OR REPLACE VIEW :"schema".incidents WITH (security_barrier) AS
  SELECT i.id, i.created_at, i.status, i.title, i.ai_verdict, i.graph
  FROM public.incidents i
  WHERE EXISTS (SELECT 1 FROM public.alerts a WHERE a.incident_id = i.id)
    AND NOT EXISTS (
      SELECT 1 FROM public.alerts a
      WHERE a.incident_id = i.id
        AND (a.asset_id IS NULL OR a.asset_id NOT IN
             (SELECT id FROM public.assets WHERE group_id = :'group_id')));

-- 处置与命令记录：只含本组资产。旧版视图带已删除的 dry_run 列，CREATE OR REPLACE 删不掉列，先整个删掉重建
DROP VIEW IF EXISTS :"schema".commands;
CREATE VIEW :"schema".commands WITH (security_barrier) AS
  SELECT id, created_at, completed_at, kind, status, asset_id, incident_id,
         issued_by, detail, cmd, exit_code, stdout, stderr, truncated
  FROM public.commands
  WHERE asset_id IN (SELECT id FROM public.assets WHERE group_id = :'group_id');

COMMENT ON SCHEMA :"schema" IS 'OpenXDR 单组只读视图，供 Pi query 工具使用';
COMMENT ON VIEW :"schema".assets IS '本组资产';
COMMENT ON VIEW :"schema".events IS '本组原始事件（OCSF 风格，raw 为 JSON）；查询务必带 ts 范围';
COMMENT ON VIEW :"schema".alerts IS '本组告警（去重后，count 为累计次数）';
COMMENT ON VIEW :"schema".incidents IS '本组 incident（全部告警都在本组）';
COMMENT ON VIEW :"schema".commands IS '本组处置与命令执行记录';
COMMENT ON VIEW :"schema".findings IS '本组运维待办（track 登记的问题，status 为 open / resolved / ignored）';
COMMENT ON VIEW :"schema".suppressions IS '本组主机上的抑制规则（status：active 生效 / proposed 待批 / rejected 已拒绝）';
COMMENT ON VIEW :"schema".memories IS '本组长期记忆（source：human 人工 / ai）';
COMMENT ON VIEW :"schema".asset_links IS '本组主机发起的连接聚合成的依赖边';
COMMENT ON VIEW :"schema".ip_infos IS '本组主机连过的公网地址：反向解析与 VirusTotal 结果';
COMMENT ON VIEW :"schema".reports IS '本组历史报告（level：ok / attention / urgent）';

-- 登录角色：不可登录管理、不可绕过 RLS，只读、5 秒超时、少量连接
SELECT format('CREATE ROLE %I LOGIN', :'role')
  WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role') \gexec
ALTER ROLE :"role" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  CONNECTION LIMIT 5 PASSWORD :'password';
ALTER ROLE :"role" SET search_path = :"schema";
ALTER ROLE :"role" SET default_transaction_read_only = on;
ALTER ROLE :"role" SET statement_timeout = '5s';

GRANT CONNECT ON DATABASE openxdr TO :"role";
GRANT USAGE ON SCHEMA :"schema" TO :"role";
GRANT SELECT ON ALL TABLES IN SCHEMA :"schema" TO :"role";

COMMIT;
