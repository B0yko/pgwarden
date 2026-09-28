#!/usr/bin/env bash
# Local Postgres 16 for the test suite. Not part of the compose demo stack.
#
# Usage:
#   devtools/testpg.sh up    # start pgwarden-testpg on 127.0.0.1:55433, write .pgwarden-test/admin_dsn
#   devtools/testpg.sh down  # stop and remove the container and its volume
#   devtools/testpg.sh env   # print `export PGWARDEN_TEST_ADMIN_DSN=...` for the current admin_dsn
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
STATE_DIR="${REPO_ROOT}/.pgwarden-test"
DSN_FILE="${STATE_DIR}/admin_dsn"
CONTAINER=pgwarden-testpg
PORT=55433
DOCKER="${DOCKER:-docker}"

cmd_up() {
  mkdir -p "${STATE_DIR}"
  chmod 700 "${STATE_DIR}"

  if "${DOCKER}" inspect "${CONTAINER}" >/dev/null 2>&1; then
    echo "container ${CONTAINER} already exists; run 'down' first to reset it" >&2
    if [[ -f "${DSN_FILE}" ]]; then
      echo "reusing existing ${DSN_FILE}" >&2
      exit 0
    fi
    exit 1
  fi

  local password
  password="$(openssl rand -hex 24)"

  "${DOCKER}" run -d \
    --name "${CONTAINER}" \
    -p "127.0.0.1:${PORT}:5432" \
    -e POSTGRES_PASSWORD="${password}" \
    -e POSTGRES_USER=postgres \
    postgres:16 >/dev/null

  echo "postgresql://postgres:${password}@127.0.0.1:${PORT}/postgres" >"${DSN_FILE}"
  chmod 600 "${DSN_FILE}"

  echo -n "waiting for ${CONTAINER} to accept connections"
  for _ in $(seq 1 60); do
    if "${DOCKER}" exec "${CONTAINER}" pg_isready -U postgres >/dev/null 2>&1; then
      echo " ready"
      exit 0
    fi
    echo -n "."
    sleep 1
  done
  echo " timed out" >&2
  exit 1
}

cmd_down() {
  "${DOCKER}" rm -f "${CONTAINER}" >/dev/null 2>&1 || true
  rm -f "${DSN_FILE}"
}

cmd_env() {
  if [[ ! -f "${DSN_FILE}" ]]; then
    echo "no ${DSN_FILE}; run 'devtools/testpg.sh up' first" >&2
    exit 1
  fi
  echo "export PGWARDEN_TEST_ADMIN_DSN=$(cat "${DSN_FILE}")"
}

case "${1:-}" in
  up) cmd_up ;;
  down) cmd_down ;;
  env) cmd_env ;;
  *)
    echo "usage: $0 {up|down|env}" >&2
    exit 2
    ;;
esac
