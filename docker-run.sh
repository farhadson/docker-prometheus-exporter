#!/usr/bin/env bash
set -euo pipefail

read -s -p "Enter remote_write password: " pass
echo
tmpfile=$(mktemp)
trap 'rm -f "$tmpfile"' EXIT
printf '%s\n' "$pass" > "$tmpfile"

docker run \
  --env-file .env \
  -v /run_files/reset_sidecar.jsonl:/var/lib/reset-sidecar/reset_sidecar.jsonl \
  -v "$tmpfile":/etc/reset-sidecar/remote_write_pass:ro \
  -p 9110:9110 \
  my-reset-sidecar:latest