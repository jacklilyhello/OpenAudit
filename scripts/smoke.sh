#!/bin/sh
set -eu

BASE_URL="${OPENAUDIT_SMOKE_URL:-http://127.0.0.1:8080}"
CONFIG_ARG=""
if [ -n "${OPENAUDIT_CONFIG:-}" ]; then
  CONFIG_ARG="--config ${OPENAUDIT_CONFIG}"
fi

SERVER_PID=""
cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# shellcheck disable=SC2086
go run ./cmd/server $CONFIG_ARG >/tmp/openaudit-smoke.log 2>&1 &
SERVER_PID=$!

ready=0
i=0
while [ "$i" -lt 30 ]; do
  if curl -fsS "$BASE_URL/health" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    cat /tmp/openaudit-smoke.log >&2 || true
    echo "OpenAudit server exited before becoming healthy" >&2
    exit 1
  fi
  i=$((i + 1))
  sleep 1
done

if [ "$ready" -ne 1 ]; then
  cat /tmp/openaudit-smoke.log >&2 || true
  echo "Timed out waiting for $BASE_URL/health" >&2
  exit 1
fi

curl -fsS "$BASE_URL/health" >/dev/null
curl -fsS "$BASE_URL/version" >/dev/null
curl -fsS "$BASE_URL/rules/stats" >/dev/null
curl -fsS -X POST "$BASE_URL/audit/text" \
  -H 'Content-Type: application/json' \
  -d '{"text":"demo content with epochtimes.com and 法輪功","options":{"normalize":true,"max_hits":10}}' >/dev/null

echo "OpenAudit smoke test passed"
