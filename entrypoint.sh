#!/usr/bin/env bash
set -euo pipefail

# If user passed raw args, just run the binary with them
# Example: docker run image --targets=... --remote-write-user=...
if [ "$#" -gt 0 ]; then
  exec /usr/local/bin/reset-sidecar-four "$@"
fi

# Otherwise construct args from environment variables (if present)
args=()

# helper to append args only if var is non-empty
append_if_set() {
  local flag="$1"; local val="$2"
  if [ -n "$val" ]; then
    args+=("$flag" "$val")
  fi
}

append_if_set "--targets" "${TARGETS:-}"
append_if_set "--metrics" "${METRICS:-}"
append_if_set "--metrics-path" "${METRICS_PATH:-}"
append_if_set "--passthrough-labels" "${PASSTHROUGH_LABELS:-}"
append_if_set "--listen-addr" "${LISTEN_ADDR:-:9110}"
append_if_set "--output-file" "${OUTPUT_FILE:-/var/lib/reset-sidecar/reset_sidecar.jsonl}"
# append_if_set "--log-file" "${LOG_FILE:-/var/log/reset-sidecar/app.log}"
append_if_set "--remote-write-url" "${REMOTE_WRITE_URL:-}"
append_if_set "--remote-write-user" "${REMOTE_WRITE_USER:-}"

### the entrypoint.sh is in container domain and so is every other file which you are checking
if [[ -f /etc/reset-sidecar/remote_write_pass ]]; then
  REMOTE_WRITE_PASS=$(cat /etc/reset-sidecar/remote_write_pass)
fi
append_if_set "--remote-write-pass" "${REMOTE_WRITE_PASS:-}"

if [[ -f /etc/reset-sidecar/custom.ca ]]; then
   REMOTE_WRITE_CA_FILE="/etc/reset-sidecar/custom.ca"
else
   REMOTE_WRITE_CA_FILE=""
fi
append_if_set "--remote-write-ca-file" "${REMOTE_WRITE_CA_FILE:-/etc/reset-sidecar/root-ca.pem}"

if [ "${REMOTE_WRITE_INSECURE_SKIP_VERIFY,,}" = "true" ]; then
  args+=("--remote-write-insecure-skip-verify=true")
fi

# Scrape TLS / mTLS (applies to all HTTPS scrape targets in the Go binary)
append_if_set "--tls_targets_ca" "${TLS_TARGETS_CA:-}"
append_if_set "--tls_cert" "${TLS_CERT:-}"
append_if_set "--tls_key" "${TLS_KEY:-}"

append_if_set "--scrape-interval" "${SCRAPE_INTERVAL:-}"
append_if_set "--publish-interval" "${PUBLISH_INTERVAL:-}"
append_if_set "--timezone" "${TIMEZONE:-}"
append_if_set "--job" "${JOB:-}"

# Log file: prefer LOG_FILE; fallback to LOG_FILENAME; default stays under /var/log/reset-sidecar
if [ -z "${LOG_FILE:-}" ] && [ -n "${LOG_FILENAME:-}" ]; then
  LOG_FILE="${LOG_FILENAME}"
fi
append_if_set "--log-file" "${LOG_FILE:-/var/log/reset-sidecar/app.log}"

if [ "${VERBOSE,,}" = "true" ]; then
  args+=("--verbose")
fi

echo "Running with args: ${args[*]}" >&2
echo "Starting reset-sidecar..."

# Ensure default log directory exists if using the default path
mkdir -p /var/log/reset-sidecar

# Let the Go binary handle writing to the log file; no more tee here
exec /usr/local/bin/reset-sidecar-four "${args[@]}"
