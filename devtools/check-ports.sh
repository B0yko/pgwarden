#!/usr/bin/env bash
# Fail with a clear message if a host port the demo stack publishes is taken.
# Reads the ports from .env (or the defaults), exactly as compose.yaml does.
#   devtools/check-ports.sh && docker compose up -d --wait
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -f .env ]]; then
    set -a
    # shellcheck disable=SC1091
    . ./.env
    set +a
fi
busy=0
summary=""
for spec in POSTGRES_PORT:5432 GATEWAY_PORT:8080 IDP_PORT:9400 MAILPIT_SMTP_PORT:1025 MAILPIT_WEB_PORT:8025; do
    name="${spec%%:*}"
    default="${spec##*:}"
    port="${!name:-$default}"
    if ! python3 -c 'import socket,sys; s=socket.socket(); s.bind(("127.0.0.1", int(sys.argv[1]))); s.close()' "$port" 2>/dev/null; then
        echo "port $port ($name) is already in use on 127.0.0.1; set $name in .env to a free port" >&2
        busy=1
    fi
    summary="$summary $name=$port"
done
if [[ $busy -ne 0 ]]; then
    exit 1
fi
echo "ports free:$summary"
