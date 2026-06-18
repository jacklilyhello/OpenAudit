#!/bin/sh
set -eu

API_KEY="${OPENAUDIT_E2E_API_KEY:-dev-key}"
BASE_URL="${OPENAUDIT_E2E_BASE_URL:-}"
TMP_DIR=""
SERVER_PID=""
SERVER_LOG=""
RULE_ID="e2e_keyword_rule"

cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT INT TERM

fail() {
  echo "E2E failed: $*" >&2
  if [ -n "$SERVER_LOG" ] && [ -f "$SERVER_LOG" ]; then
    echo "--- server log ---" >&2
    cat "$SERVER_LOG" >&2 || true
    echo "--- end server log ---" >&2
  fi
  exit 1
}

request() {
  method="$1"
  path="$2"
  expected="$3"
  body="${4:-}"
  out="$TMP_DIR/response.json"
  code="$TMP_DIR/status.txt"
  if [ -n "$body" ]; then
    status=$(curl --max-time 10 -sS -o "$out" -w '%{http_code}' -X "$method" "$BASE_URL$path" \
      -H 'Content-Type: application/json' \
      -H "Authorization: Bearer $API_KEY" \
      -H "X-API-Key: $API_KEY" \
      -d "$body") || fail "$method $path curl failed"
  else
    status=$(curl --max-time 10 -sS -o "$out" -w '%{http_code}' -X "$method" "$BASE_URL$path" \
      -H 'Content-Type: application/json' \
      -H "Authorization: Bearer $API_KEY" \
      -H "X-API-Key: $API_KEY") || fail "$method $path curl failed"
  fi
  printf '%s' "$status" > "$code"
  [ "$status" = "$expected" ] || fail "$method $path returned HTTP $status, expected $expected: $(cat "$out")"
}

assert_contains() {
  file="$1"
  needle="$2"
  if ! grep -F "$needle" "$file" >/dev/null 2>&1; then
    fail "response did not contain '$needle': $(cat "$file")"
  fi
}

if [ -n "$BASE_URL" ]; then
  TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/openaudit-e2e.XXXXXX")
  echo "OpenAudit E2E: using external-server mode at $BASE_URL"
else
  TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/openaudit-e2e.XXXXXX")
  SERVER_LOG="$TMP_DIR/server.log"
  PORT="${OPENAUDIT_E2E_PORT:-18080}"
  BASE_URL="http://127.0.0.1:$PORT"
  mkdir -p "$TMP_DIR/data" "$TMP_DIR/storage/data" "$TMP_DIR/storage/rule-history/snapshots" "$TMP_DIR/imports/reports"
  cat > "$TMP_DIR/config.yml" <<EOF_CONFIG
app:
  env: "development"
server:
  addr: "127.0.0.1:$PORT"
  read_timeout_seconds: 10
  write_timeout_seconds: 30
  trusted_proxies: ["127.0.0.1/32", "::1/128"]
rules:
  data_dir: "$TMP_DIR/data"
  auto_reload: false
admin:
  enabled: false
security:
  api_key_enabled: true
  api_keys: ["$API_KEY"]
  protected_paths: ["/rules/reload", "/rules/create", "/rules/update", "/rules/delete", "/logs", "/config", "/storage", "/review"]
  allow_admin_without_key: false
  protect_audit_api: false
  protect_management_api: true
security_headers:
  enabled: true
cors:
  enabled: false
rate_limit:
  enabled: false
audit_log:
  enabled: true
  path: "$TMP_DIR/storage/audit.log"
  max_entries: 1000
  log_request_text: false
  log_hits: true
storage:
  backend: "sqlite"
  root: "$TMP_DIR/storage"
  sqlite_path: "data/openaudit.db"
  legacy_jsonl_fallback: false
  auto_migrate: true
limits:
  max_text_runes: 10000
  max_batch_items: 100
  max_hits: 100
  max_body_bytes: 1048576
ai:
  enabled: false
  default_action: "review"
  hard_block_enabled: false
  provider: "local"
  model: ""
  timeout_ms: 1000
  max_retries: 0
  retry_backoff_ms: 0
  circuit_breaker_failure_threshold: 1
  circuit_breaker_cooldown_ms: 1000
  max_excerpt_runes: 2000
  cache:
    enabled: false
  cost_tracking:
    enabled: false
  audit_logs:
    enabled: false
    store_prompts: false
    store_raw_response: false
  providers:
    openai: {enabled: false}
    deepseek: {enabled: false}
    qwen: {enabled: false}
    gemini: {enabled: false}
    claude: {enabled: false}
    local: {enabled: false, base_url: "http://127.0.0.1:9/v1", model: "disabled"}
review_policy:
  enabled: true
  ai_review_enabled: false
  variant_review_enabled: false
  uncertain_default_action: "temporary_allow"
  retention_days: 30
  content_excerpt_max_bytes: 2048
  max_export_rows: 10000
rule_history:
  enabled: true
  path: "$TMP_DIR/storage/rule-history/history.jsonl"
  import_batches_path: "$TMP_DIR/storage/rule-history/import-batches.jsonl"
  max_entries: 5000
  snapshot_dir: "$TMP_DIR/storage/rule-history/snapshots"
importer:
  default_input_dir: "$TMP_DIR/imports/input"
  default_output_dir: "$TMP_DIR/data/imported"
  report_dir: "$TMP_DIR/imports/reports"
  batch_history_path: "$TMP_DIR/storage/rule-history/import-batches.jsonl"
  max_keywords_per_file: 10000
  default_source: "external"
  auto_reload_after_import: false
  allow_remote_clone: false
  allowed_clone_hosts: []
EOF_CONFIG
  echo "OpenAudit E2E: using temporary local server mode at $BASE_URL"
  go run ./cmd/server --config "$TMP_DIR/config.yml" >"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
  i=0
  while [ "$i" -lt 120 ]; do
    if curl --max-time 2 -fsS "$BASE_URL/health" >/dev/null 2>&1; then
      break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      fail "local server exited before becoming healthy"
    fi
    i=$((i + 1))
    sleep 1
  done
  [ "$i" -lt 120 ] || fail "timed out waiting for $BASE_URL/health"
fi

request GET /health 200
assert_contains "$TMP_DIR/response.json" '"status":"ok"'
request GET /version 200
assert_contains "$TMP_DIR/response.json" '"service":"OpenAudit"'
request POST /audit/text 200 '{"text":"phase 16 deterministic e2e sample before rule creation","options":{"max_hits":5}}'
assert_contains "$TMP_DIR/response.json" '"action"'
request POST /rules/create 200 '{"rule":{"id":"e2e_keyword_rule","type":"keyword","category":"e2e","risk_level":"medium","action":"review","score":60,"enabled":true,"keywords":["phase16-e2e-keyword"]}}'
assert_contains "$TMP_DIR/response.json" '"ok":true'
request PATCH /rules/update/$RULE_ID 200 '{"patch":{"score":61,"keywords":["phase16-e2e-keyword","phase16-e2e-updated"]}}'
assert_contains "$TMP_DIR/response.json" '"ok":true'
request POST /rules/reload 200 '{}'
assert_contains "$TMP_DIR/response.json" '"ok":true'
request POST /audit/text 200 '{"text":"phase16-e2e-updated should match the deterministic rule","options":{"max_hits":5}}'
assert_contains "$TMP_DIR/response.json" 'e2e_keyword_rule'
request GET '/storage/audit_logs?limit=1' 200
assert_contains "$TMP_DIR/response.json" '"items"'
request GET '/review/cases?limit=1' 200
assert_contains "$TMP_DIR/response.json" '"items"'

echo "OpenAudit E2E verification passed"
