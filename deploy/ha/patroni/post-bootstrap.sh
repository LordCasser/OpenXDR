#!/bin/sh
set -eu
psql "$1" -v ON_ERROR_STOP=1 \
  -v openxdr_password="$OPENXDR_PASSWORD" \
  -v replication_password="$REPLICATION_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE openxdr LOGIN CREATEDB PASSWORD %L', :'openxdr_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openxdr') \gexec
SELECT format('CREATE ROLE replicator LOGIN REPLICATION PASSWORD %L', :'replication_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'replicator') \gexec
SELECT 'CREATE DATABASE openxdr OWNER openxdr'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'openxdr') \gexec
SQL
