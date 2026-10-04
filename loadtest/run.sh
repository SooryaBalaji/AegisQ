#!/usr/bin/env bash
# Run the AegisQ k6 load tests end to end.
#
#   loadtest/run.sh                 # full size
#   SMOKE=1 loadtest/run.sh         # a few seconds per scenario (CI)
#   SCENARIOS="api approvals" loadtest/run.sh
#
# Scenarios: api, approvals, tls, auth (auth runs last because it trips the login throttle).
# Uses a local `k6` if installed, otherwise the grafana/k6 Docker image.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
OUT="$HERE/out"
PORT="${PORT:-8765}"
SERVICES="${SERVICES:-2000}"
AUDIT="${AUDIT:-20000}"
APPROVALS="${APPROVALS:-200}"
SCENARIOS="${SCENARIOS:-api approvals tls auth}"
if [[ "${SMOKE:-0}" == "1" ]]; then SERVICES=${SERVICES_SMOKE:-300}; AUDIT=${AUDIT_SMOKE:-2000}; APPROVALS=${APPROVALS_SMOKE:-40}; fi

HOME_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegisq-loadtest.XXXXXX")"
rm -rf "$OUT" && mkdir -p "$OUT"
TOKENS="alice:$(openssl rand -hex 16),bob:$(openssl rand -hex 16)"

if command -v k6 >/dev/null 2>&1; then
  K6=(k6); SCRIPT_DIR="$HERE"
else
  K6=(docker run --rm -i --network host --user "$(id -u):$(id -g)" -v "$HERE:/scripts" -w /scripts grafana/k6:latest); SCRIPT_DIR="/scripts"
fi

server_pid=""
cleanup() { [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null || true; rm -rf "$HOME_DIR"; }
trap cleanup EXIT

echo "== seeding $HOME_DIR ($SERVICES services, $AUDIT audit entries, $APPROVALS approvals)"
python3 "$HERE/seed.py" seed --home "$HOME_DIR" --out "$OUT" \
  --services "$SERVICES" --audit "$AUDIT" --approvals "$APPROVALS"

start_server() {
  [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null && wait "$server_pid" 2>/dev/null || true
  AEGISQ_HOME="$HOME_DIR" AEGISQ_API_TOKENS="$TOKENS" aegisq serve --port "$PORT" >"$OUT/server.log" 2>&1 &
  server_pid=$!
  for _ in $(seq 1 50); do curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && return; sleep 0.2; done
  echo "server did not start"; cat "$OUT/server.log"; exit 1
}

status=0
run() {
  local name="$1" script="$2"
  echo "== k6: $name"
  if "${K6[@]}" run --quiet \
      -e BASE_URL="http://127.0.0.1:$PORT" -e TOKENS="$TOKENS" -e SMOKE="${SMOKE:-0}" \
      -e APPROVALS_FILE="$SCRIPT_DIR/out/approvals.json" \
      --summary-export "$SCRIPT_DIR/out/$name-summary.json" "$SCRIPT_DIR/$script"; then
    echo "-- $name: thresholds passed"
  else
    echo "-- $name: THRESHOLDS FAILED"; status=1
  fi
}

start_server
for s in $SCENARIOS; do
  case "$s" in
    api) run api api-read.js ;;
    approvals)
      run approvals approvals.js
      echo "== verifying workspace integrity"
      python3 "$HERE/seed.py" verify --home "$HOME_DIR" --out "$OUT" || status=1 ;;
    tls)
      if curl -sk -o /dev/null https://127.0.0.1:8446/ && curl -sk -o /dev/null https://127.0.0.1:8443/; then
        run tls tls-handshake.js
      else
        echo "== skipping tls: demo fleet not running (make demo-up)"
      fi ;;
    auth) start_server; run auth auth.js ;;
    *) echo "unknown scenario $s"; exit 2 ;;
  esac
done
echo "summaries in $OUT"
exit $status
