#!/usr/bin/env bash
set -euo pipefail

# Load .env into current shell (ignores comments and blank lines)
if [[ -f .env ]]; then
  # shellcheck disable=SC2046
  export $(grep -vE '^\s*#' .env | grep -vE '^\s*$' | xargs)
fi

# Prompt for password; do NOT store in .env
read -s -p "Enter remote_write password: " pass
echo
tmpfile=$(mktemp)
trap 'rm -f "$tmpfile"' EXIT
printf '%s\n' "$pass" > "$tmpfile"

# Optional: expose pass file via env if your binary can use it
export REMOTE_WRITE_PASS_FILE="$tmpfile"

# Build boolean flags conditionally
bool_flags=()

# VERBOSE: only add --verbose when true
if [[ "${VERBOSE:-false}" == "true" ]]; then
  bool_flags+=(--verbose)
fi

# REMOTE_WRITE_INSECURE_SKIP_VERIFY: only add flag when true
if [[ "${REMOTE_WRITE_INSECURE_SKIP_VERIFY:-false}" == "true" ]]; then
  bool_flags+=(--remote-write-insecure-skip-verify)
fi

### if you need to override .env
# JOB="temp-job"
# SCRAPE_INTERVAL="10s"
# VERBOSE=true

./reset-sidecar-four \
  --targets="${TARGETS:?TARGETS is required}" \
  --metrics="${METRICS:?METRICS is required}" \
  --metrics-path="${METRICS_PATH:-/metrics}" \
  --passthrough-labels="${PASSTHROUGH_LABELS:-}" \
  --listen-addr="${LISTEN_ADDR:-:9110}" \
  --output-file="${OUTPUT_FILE:-/var/lib/reset-sidecar/reset_sidecar.jsonl}" \
  --log-filename="${LOG_FILENAME:-app.log}" \
  --remote-write-url="${REMOTE_WRITE_URL:?REMOTE_WRITE_URL is required}" \
  --remote-write-user="${REMOTE_WRITE_USER:?REMOTE_WRITE_USER is required}" \
  --remote-write-server-name="${REMOTE_WRITE_SERVER_NAME:-}" \
  --scrape-interval="${SCRAPE_INTERVAL:-30s}" \
  --publish-interval="${PUBLISH_INTERVAL:-60s}" \
  --timezone="${TIMEZONE:-UTC}" \
  --job="${JOB:-reset-sidecar}" \
  --remote-write-pass-file="${REMOTE_WRITE_PASS_FILE}" \
  "${bool_flags[@]}"
