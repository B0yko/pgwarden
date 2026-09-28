#!/usr/bin/env bash
# Host wrapper for the benchmark compose profile (README, "Latency and load").
#
# The clients run in the `bench` container, which has no Docker socket, so this script does
# what only the host can: it switches the stack to the bench config, records the facts the
# container cannot see (commit, colima CPUs and memory, other running containers, Postgres
# version), samples the gateway from outside while the load runs, verifies the audit chain
# afterwards, and merges everything into docs/results/{latency,load}-<date>.json.
#
# Usage (from a clone, with the demo stack's .env in place and `uv sync` done):
#   devtools/bench/run.sh latency   # 3 repetitions x 1000 iterations (100 warmup) -> latency-<date>.json
#   devtools/bench/run.sh cold      # cold first-query cost on the 1 s pool-idle config; adds it to
#                                   # the latency file, so run `latency` first
#   devtools/bench/run.sh load      # 20 identities, concurrency 20, 60 s -> load-<date>.json
#   devtools/bench/run.sh all       # latency, cold and load, in that order
#   devtools/bench/run.sh restore   # put the stack back on the default demo config
#
# Environment (all optional):
#   PGWARDEN_RUN_DATE          date in the file names and in the results (default: today)
#   PGWARDEN_BENCH_MACHINE     "<machine>, <RAM>" in the hardware string, for example
#                              "MacBook Air M5, 24 GB" (default: the CPU brand and RAM)
#   PGWARDEN_BENCH_RESULTS_DIR where the JSON goes (default: docs/results)
#   PGWARDEN_BENCH_LOAD_ARGS   arguments of `pgwarden bench load` (default:
#                              "--identities 20 --concurrency 20 --duration 60 --mix pk:60,filter:30,agg:10")
#
# Sampled from the host while the load runs, at least once a second (docker stats streams
# about two frames a second, the two polls run about every half second): the gateway's CPU
# (docker stats, percent of one core), its RSS (VmRSS of the server process), and the Postgres
# connections held by pgwarden's roles (pg_stat_activity, through the postgres container).
# The results file records how many samples each one got.
# The stack is left on the bench config; `restore` undoes that.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

DATE="${PGWARDEN_RUN_DATE:-$(date +%Y-%m-%d)}"
RESULTS="${PGWARDEN_BENCH_RESULTS_DIR:-docs/results}"
LOAD_ARGS="${PGWARDEN_BENCH_LOAD_ARGS:---identities 20 --concurrency 20 --duration 60 --mix pk:60,filter:30,agg:10}"
BENCH_CONFIG="pgwarden.bench.yaml"
COLD_CONFIG="pgwarden.bench-cold.yaml"

# Same statement as pgwarden.bench.load.PEAK_CONNECTIONS_SQL (a unit test keeps them equal).
read -r -d '' PEAK_SQL <<'SQL' || true
SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND usename LIKE 'pw\_%'
SQL

log() { echo "[bench] $*" >&2; }
die() { echo "[bench] error: $*" >&2; exit 1; }

command -v docker >/dev/null || die "docker is not on PATH (colima's CLI: ~/.local/bin/docker)"
command -v uv >/dev/null || die "uv is not on PATH"

SAMPLES_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pgwarden-bench.XXXXXX")"
SAMPLER_PIDS=()
cleanup() {
  for pid in "${SAMPLER_PIDS[@]:-}"; do
    [ -n "${pid}" ] && kill "${pid}" 2>/dev/null || true
  done
  rm -rf "${SAMPLES_DIR}"
}
trap cleanup EXIT

fresh_dir() { rm -rf "${SAMPLES_DIR:?}"/*; }

stack_up_bench() {
  log "stack on ${BENCH_CONFIG} (rebuilds the image from this checkout)"
  PGWARDEN_DEMO_CONFIG="${BENCH_CONFIG}" docker compose up -d --build --wait >&2
}

gateway_to_cold() {
  log "gateway on ${COLD_CONFIG} (pool.idle_timeout_s: 1)"
  PGWARDEN_DEMO_CONFIG="${COLD_CONFIG}" docker compose up -d --no-deps --wait gateway >&2
}

# Facts only the host knows, exported for the bench container (see compose.yaml).
host_facts() {
  local colima_json cpus mem_bytes mem_gib machine ram_gib project total ours
  colima_json="$(colima list --json 2>/dev/null | head -n 1 || true)"
  cpus="$(sed -n 's/.*"cpus":\([0-9]*\).*/\1/p' <<<"${colima_json}")"
  mem_bytes="$(sed -n 's/.*"memory":\([0-9]*\).*/\1/p' <<<"${colima_json}")"
  [ -n "${cpus}" ] && [ -n "${mem_bytes}" ] || die "cannot read colima's CPUs and memory (colima list --json)"
  mem_gib=$((mem_bytes / 1024 / 1024 / 1024))
  if [ -n "${PGWARDEN_BENCH_MACHINE:-}" ]; then
    machine="${PGWARDEN_BENCH_MACHINE}"
  else
    ram_gib=$(($(sysctl -n hw.memsize) / 1024 / 1024 / 1024))
    machine="$(sysctl -n machdep.cpu.brand_string), ${ram_gib} GB"
  fi
  project="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$(docker compose ps -q gateway)")"
  total="$(docker ps -q | wc -l | tr -d ' ')"
  ours="$(docker ps -q --filter "label=com.docker.compose.project=${project}" | wc -l | tr -d ' ')"

  export PGWARDEN_RUN_DATE="${DATE}"
  PGWARDEN_GIT_COMMIT="$(git rev-parse --short HEAD)"
  if [ -n "$(git status --porcelain -- src demo compose.yaml Dockerfile pyproject.toml uv.lock)" ]; then
    PGWARDEN_GIT_COMMIT="${PGWARDEN_GIT_COMMIT}-dirty"
    log "warning: uncommitted changes in the code under test, the commit is recorded as ${PGWARDEN_GIT_COMMIT}"
  fi
  export PGWARDEN_GIT_COMMIT
  export PGWARDEN_BENCH_HARDWARE="${machine}, Docker via colima with ${cpus} CPUs / ${mem_gib} GB"
  export PGWARDEN_BENCH_COLIMA_CPUS="${cpus}"
  export PGWARDEN_BENCH_COLIMA_MEMORY_GIB="${mem_gib}"
  export PGWARDEN_BENCH_OTHER_CONTAINERS=$((total - ours))
  PGWARDEN_BENCH_POSTGRES_VERSION="$(docker compose exec -T postgres psql -U postgres -d shop -Atc 'SHOW server_version' | tr -d '\r')"
  export PGWARDEN_BENCH_POSTGRES_VERSION
  log "hardware: ${PGWARDEN_BENCH_HARDWARE}; other running containers: ${PGWARDEN_BENCH_OTHER_CONTAINERS}; commit ${PGWARDEN_GIT_COMMIT}"
}

# run_bench <config file> <pgwarden args...>; the JSON document goes to stdout.
run_bench() {
  local config="$1"
  shift
  PGWARDEN_DEMO_CONFIG="${config}" docker compose --profile bench run --rm --no-deps -T bench pgwarden "$@"
}

start_samplers() {
  local gateway postgres
  gateway="$(docker compose ps -q gateway)"
  postgres="$(docker compose ps -q postgres)"
  : >"${SAMPLES_DIR}/gateway-rss.txt"
  : >"${SAMPLES_DIR}/pg-connections.txt"
  docker stats --format '{{.CPUPerc}}|{{.MemUsage}}' "${gateway}" >"${SAMPLES_DIR}/docker-stats.txt" 2>/dev/null &
  SAMPLER_PIDS+=("$!")
  (
    while :; do
      docker exec "${gateway}" grep VmRSS /proc/1/status >>"${SAMPLES_DIR}/gateway-rss.txt" 2>/dev/null || true
      sleep 0.3
    done
  ) &
  SAMPLER_PIDS+=("$!")
  (
    while :; do
      docker exec "${postgres}" psql -U postgres -d shop -Atc "${PEAK_SQL}" >>"${SAMPLES_DIR}/pg-connections.txt" 2>/dev/null || true
      sleep 0.3
    done
  ) &
  SAMPLER_PIDS+=("$!")
}

stop_samplers() {
  for pid in "${SAMPLER_PIDS[@]:-}"; do
    [ -n "${pid}" ] && kill "${pid}" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  SAMPLER_PIDS=()
}

verify_audit() {
  log "pgwarden audit verify"
  local code=0
  docker compose exec -T gateway pgwarden audit verify >"${SAMPLES_DIR}/audit-verify.txt" 2>&1 || code=$?
  echo "${code}" >"${SAMPLES_DIR}/audit-verify.exit"
  cat "${SAMPLES_DIR}/audit-verify.txt" >&2
}

merge() { uv run pgwarden bench merge "$@" --samples-dir "${SAMPLES_DIR}"; }

phase_latency() {
  stack_up_bench
  host_facts
  fresh_dir
  log "latency: 3 repetitions x 1000 iterations, 100 warmup (several minutes)"
  run_bench "${BENCH_CONFIG}" bench latency --iterations 1000 --warmup 100 --repetitions 3 \
    --report - >"${SAMPLES_DIR}/raw.json"
  verify_audit
  merge latency --out "${RESULTS}/latency-${DATE}.json"
}

phase_cold() {
  [ -f "${RESULTS}/latency-${DATE}.json" ] || die "run 'latency' first: ${RESULTS}/latency-${DATE}.json is missing"
  stack_up_bench
  gateway_to_cold
  host_facts
  fresh_dir
  log "cold start: 30 samples, each after 2.5 s of silence"
  run_bench "${COLD_CONFIG}" bench cold --samples 30 --idle-wait 2.5 --report - >"${SAMPLES_DIR}/raw.json"
  merge cold --out "${RESULTS}/latency-${DATE}.json"
  stack_up_bench
}

phase_load() {
  stack_up_bench
  host_facts
  fresh_dir
  log "load: ${LOAD_ARGS}"
  start_samplers
  # shellcheck disable=SC2086
  run_bench "${BENCH_CONFIG}" bench load ${LOAD_ARGS} --report - >"${SAMPLES_DIR}/raw.json"
  stop_samplers
  verify_audit
  merge load --out "${RESULTS}/load-${DATE}.json"
}

phase_restore() {
  log "stack on the default demo config"
  env -u PGWARDEN_DEMO_CONFIG docker compose up -d --wait >&2
}

case "${1:-}" in
  latency) phase_latency ;;
  cold) phase_cold ;;
  load) phase_load ;;
  all) phase_latency; phase_cold; phase_load ;;
  restore) phase_restore ;;
  *) die "usage: devtools/bench/run.sh latency|cold|load|all|restore" ;;
esac
