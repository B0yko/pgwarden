#!/bin/bash
# Postgres first-start hook (docker-entrypoint-initdb.d): create the demo target
# database `shop` and load the demo "DBA" SQL. The state database `pgwarden` is
# created later by `pgwarden db init`.
set -euo pipefail
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres -c "CREATE DATABASE shop"
for f in /demo-sql/*.sql; do
    echo "loading $f"
    psql -v ON_ERROR_STOP=1 --quiet --username "$POSTGRES_USER" --dbname shop -f "$f"
done
