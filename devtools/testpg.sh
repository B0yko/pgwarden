#!/usr/bin/env bash
# Local Postgres 16 (+ a transaction-mode PgBouncer, for doctor's pooler-mode
# test) for the test suite. Not part of the compose demo stack.
#
# Usage:
#   devtools/testpg.sh up    # start pgwarden-testpg (55433) + pgwarden-testbouncer (55434)
#   devtools/testpg.sh down  # stop and remove both containers, the network and their state
#   devtools/testpg.sh env   # print `export PGWARDEN_TEST_ADMIN_DSN=...` for the current admin_dsn
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
STATE_DIR="${REPO_ROOT}/.pgwarden-test"
DSN_FILE="${STATE_DIR}/admin_dsn"
CONTAINER=pgwarden-testpg
PORT=55433
DOCKER="${DOCKER:-docker}"

# The bouncer fixture: a real PgBouncer in transaction mode, proxying to
# pgwarden-testpg, so `pgwarden doctor`'s pooler-mode check has a real
# failing case to detect (see tests/integration/test_doctor.py). Pinned by
# digest (resolved from edoburu/pgbouncer:latest; PgBouncer 1.25.2 inside).
BOUNCER_CONTAINER=pgwarden-testbouncer
BOUNCER_PORT=55434
BOUNCER_IMAGE="edoburu/pgbouncer@sha256:4c1ca296ef525f108f5d3552cc337c0c09587cf8dae7f0067fd93349e47dc1cd"
NETWORK=pgwarden-test-net

# The bouncer proxies to the `pw_u_alice` role in the `pgw_shop` database,
# using the exact password `pgwarden roles sync` would set for it under the
# test suite's fixed role secret (tests/conftest.py's TEST_ROLE_SECRET) --
# computed here, not hardcoded, so the two can never drift apart. Neither
# the role nor the database need to exist yet when the bouncer container
# starts: PgBouncer only looks them up when a client (a test, later) first
# connects through it, by which point the pytest session fixtures have
# created both.
bouncer_probe_password() {
  (cd "${REPO_ROOT}" && "${UV:-uv}" run python3 -c "
import tests.conftest as c
from pgwarden.db.scram import derive_password
print(derive_password(c.TEST_ROLE_SECRET, 'pw_u_alice'))
")
}

cmd_up() {
  mkdir -p "${STATE_DIR}"
  chmod 700 "${STATE_DIR}"

  "${DOCKER}" network inspect "${NETWORK}" >/dev/null 2>&1 \
    || "${DOCKER}" network create "${NETWORK}" >/dev/null

  if "${DOCKER}" inspect "${CONTAINER}" >/dev/null 2>&1; then
    echo "container ${CONTAINER} already exists; run 'down' first to reset it" >&2
    if [[ ! -f "${DSN_FILE}" ]]; then
      exit 1
    fi
    echo "reusing existing ${DSN_FILE}" >&2
  else
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
    local ready=0
    for _ in $(seq 1 60); do
      if "${DOCKER}" exec "${CONTAINER}" pg_isready -U postgres >/dev/null 2>&1; then
        echo " ready"
        ready=1
        break
      fi
      echo -n "."
      sleep 1
    done
    if [[ "${ready}" != 1 ]]; then
      echo " timed out" >&2
      exit 1
    fi
  fi

  "${DOCKER}" network connect "${NETWORK}" "${CONTAINER}" >/dev/null 2>&1 || true

  if "${DOCKER}" inspect "${BOUNCER_CONTAINER}" >/dev/null 2>&1; then
    echo "container ${BOUNCER_CONTAINER} already exists; leaving it running" >&2
  else
    local probe_password
    probe_password="$(bouncer_probe_password)"

    "${DOCKER}" run -d \
      --name "${BOUNCER_CONTAINER}" \
      --network "${NETWORK}" \
      -p "127.0.0.1:${BOUNCER_PORT}:5432" \
      -e DATABASE_URL="postgresql://pw_u_alice:${probe_password}@${CONTAINER}:5432/pgw_shop" \
      -e AUTH_TYPE=plain \
      -e POOL_MODE=transaction \
      -e DEFAULT_POOL_SIZE=1 \
      -e MAX_CLIENT_CONN=100 \
      -e SERVER_IDLE_TIMEOUT=5 \
      "${BOUNCER_IMAGE}" >/dev/null

    echo -n "waiting for ${BOUNCER_CONTAINER} to accept connections"
    local bready=0
    for _ in $(seq 1 30); do
      if (exec 3<>"/dev/tcp/127.0.0.1/${BOUNCER_PORT}") 2>/dev/null; then
        exec 3>&- 3<&-
        echo " ready"
        bready=1
        break
      fi
      echo -n "."
      sleep 1
    done
    if [[ "${bready}" != 1 ]]; then
      echo " timed out" >&2
      exit 1
    fi
  fi
}

cmd_down() {
  "${DOCKER}" rm -f "${BOUNCER_CONTAINER}" >/dev/null 2>&1 || true
  "${DOCKER}" rm -f "${CONTAINER}" >/dev/null 2>&1 || true
  "${DOCKER}" network rm "${NETWORK}" >/dev/null 2>&1 || true
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
