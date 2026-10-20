package identity

import (
	"context"
	"database/sql"
)

// ensureGraphSchema 建全局身份图的表。账号登记、身份与链接都按组隔离：
// 链接用 (group_id, id) 复合外键同时指向身份和账号，数据库层面就不可能跨组链接。
func ensureGraphSchema(ctx context.Context, db *sql.DB) error {
	// 增量游标依赖的入库时间列：已有列时不再执行 ALTER，免得每次启动都抢热表的排他锁
	for _, column := range []struct{ table, name, ddl string }{
		{"identity_observations", "recorded_at", `ALTER TABLE identity_observations ADD COLUMN IF NOT EXISTS recorded_at timestamptz NOT NULL DEFAULT now()`},
		{"identity_local_snapshots", "recorded_at", `ALTER TABLE identity_local_snapshots ADD COLUMN IF NOT EXISTS recorded_at timestamptz NOT NULL DEFAULT now()`},
		{"identity_local_snapshots", "ts", `ALTER TABLE identity_local_snapshots ADD COLUMN IF NOT EXISTS ts timestamptz`},
	} {
		var exists bool
		if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns
 WHERE table_schema=current_schema() AND table_name=$1 AND column_name=$2)`, column.table, column.name).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			if _, err := db.ExecContext(ctx, column.ddl); err != nil {
				return err
			}
		}
	}
	_, err := db.ExecContext(ctx, `
CREATE INDEX IF NOT EXISTS identity_observations_recorded ON identity_observations(recorded_at);
CREATE INDEX IF NOT EXISTS identity_local_snapshots_recorded ON identity_local_snapshots(recorded_at);
CREATE INDEX IF NOT EXISTS identity_local_snapshots_ts ON identity_local_snapshots(asset_id,group_id,ts);
CREATE INDEX IF NOT EXISTS identity_local_snapshots_missing_ts ON identity_local_snapshots(event_id) WHERE ts IS NULL;
CREATE TABLE IF NOT EXISTS identity_accounts (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 group_id uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
 kind text NOT NULL CHECK(kind IN ('directory','windows','linux')),
 account_key text NOT NULL,
 asset_id uuid REFERENCES assets(id) ON DELETE CASCADE,
 directory_account_id uuid REFERENCES identity_directory_accounts(id) ON DELETE CASCADE,
 sid text, uid bigint CHECK(uid BETWEEN 0 AND 4294967295), name text, domain text,
 first_seen timestamptz NOT NULL, last_seen timestamptz NOT NULL,
 UNIQUE(group_id,account_key), UNIQUE(group_id,id),
 CHECK((kind='directory') = (directory_account_id IS NOT NULL)),
 CHECK((kind='directory') = (asset_id IS NULL)),
 CHECK(kind<>'windows' OR sid IS NOT NULL),
 CHECK(kind<>'linux' OR (uid IS NOT NULL AND name IS NOT NULL)));
CREATE INDEX IF NOT EXISTS identity_accounts_asset ON identity_accounts(asset_id) WHERE asset_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS identity_accounts_directory ON identity_accounts(directory_account_id) WHERE directory_account_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS identity_accounts_sid ON identity_accounts(group_id,sid) WHERE sid IS NOT NULL;
CREATE INDEX IF NOT EXISTS identity_accounts_name ON identity_accounts(group_id,lower(regexp_replace(name,'^.*\\|@.*$','','g')));
CREATE TABLE IF NOT EXISTS identities (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 group_id uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
 kind text NOT NULL CHECK(kind IN ('directory','host')),
 anchor_account_id uuid NOT NULL UNIQUE,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(group_id,id),
 FOREIGN KEY(group_id,anchor_account_id) REFERENCES identity_accounts(group_id,id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS identity_links (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 group_id uuid NOT NULL,
 identity_id uuid NOT NULL,
 account_id uuid NOT NULL,
 basis text NOT NULL CHECK(basis IN ('directory_anchor','ad_sid','host_local','manual')),
 confidence text NOT NULL CHECK(confidence IN ('authoritative','strong','local','manual')),
 evidence jsonb NOT NULL,
 source text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 revoked_at timestamptz, revoked_by text, revoke_reason text,
 CHECK((revoked_at IS NULL) = (revoked_by IS NULL) AND (revoked_at IS NULL) = (revoke_reason IS NULL)),
 FOREIGN KEY(group_id,identity_id) REFERENCES identities(group_id,id) ON DELETE CASCADE,
 FOREIGN KEY(group_id,account_id) REFERENCES identity_accounts(group_id,id) ON DELETE CASCADE);
CREATE UNIQUE INDEX IF NOT EXISTS identity_links_active ON identity_links(account_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS identity_links_identity ON identity_links(identity_id,created_at DESC);
CREATE INDEX IF NOT EXISTS identity_links_account ON identity_links(account_id);
CREATE TABLE IF NOT EXISTS identity_candidate_rejections (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 group_id uuid NOT NULL,
 identity_id uuid NOT NULL,
 account_id uuid NOT NULL,
 created_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 revoked_at timestamptz, revoked_by text,
 CHECK((revoked_at IS NULL) = (revoked_by IS NULL)),
 FOREIGN KEY(group_id,identity_id) REFERENCES identities(group_id,id) ON DELETE CASCADE,
 FOREIGN KEY(group_id,account_id) REFERENCES identity_accounts(group_id,id) ON DELETE CASCADE);
CREATE UNIQUE INDEX IF NOT EXISTS identity_candidate_rejections_active ON identity_candidate_rejections(identity_id,account_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS identity_candidate_rejections_account ON identity_candidate_rejections(account_id);
CREATE TABLE IF NOT EXISTS identity_login_matches (
 event_id uuid PRIMARY KEY REFERENCES identity_observations(event_id) ON DELETE CASCADE,
 group_id uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
 asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
 ts timestamptz NOT NULL, account_name text NOT NULL, success boolean NOT NULL, source_address text,
 state text NOT NULL CHECK(state IN ('matched','no_account','no_snapshot','snapshot_unavailable')),
 snapshot_event_id uuid REFERENCES identity_local_snapshots(event_id) ON DELETE SET NULL,
 snapshot_ts timestamptz, uid bigint,
 matched_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((state='matched') = (uid IS NOT NULL)));
CREATE INDEX IF NOT EXISTS identity_login_matches_asset ON identity_login_matches(asset_id,ts);
CREATE INDEX IF NOT EXISTS identity_login_matches_snapshot ON identity_login_matches(snapshot_event_id) WHERE snapshot_event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS identity_login_matches_account ON identity_login_matches(asset_id,uid,account_name,ts) WHERE state='matched';
CREATE TABLE IF NOT EXISTS identity_graph_cursors (name text PRIMARY KEY, at timestamptz NOT NULL);`)
	return err
}
