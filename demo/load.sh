#!/usr/bin/env bash
# Applies demo/sql/*.sql, in filename order, over one psql connection.
#
# Usage: demo/load.sh <admin DSN naming the target database>
# Example: demo/load.sh postgresql://postgres:secret@127.0.0.1:5432/shop
set -euo pipefail

DSN="${1:?usage: demo/load.sh <admin dsn naming the target database>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for f in "${SCRIPT_DIR}"/sql/*.sql; do
  echo "applying $(basename "${f}")"
  psql "${DSN}" -v ON_ERROR_STOP=1 -q -f "${f}"
done
