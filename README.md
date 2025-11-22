# 🧰 reset-sidecar — Multi-sink Counter Reset Tracker

This containerized sidecar scrapes Prometheus endpoints, detects counter resets, and republishes consistent metric streams across multiple sinks (expose, Pushgateway, remote_write, and file).

---

## 🚀 Build-time configuration

The image is built using a multi-stage Dockerfile. You can customize the Go module proxy at build time:

| Build arg | Default                                         | Description                                                                 |
|-----------|-------------------------------------------------|-----------------------------------------------------------------------------|
| `GOPROXY` | `https://jfrog.partdp.ai/artifactory/api/go/go` | Primary Go module proxy; `,direct` is appended so direct fallback is enabled |

Example:

```
docker build \
  --build-arg GOPROXY=https://jfrog.partdp.ai/artifactory/api/go/go \
  -t my-reset-sidecar:latest .
```

The builder stage uses:

- `GOOS=linux`
- `GOARCH=amd64`
- `CGO_ENABLED=0`

to produce a static-ish binary suitable for the slim Debian runtime.

---

## 🧩 Runtime model (env vs CLI)

At runtime, the container runs `entrypoint.sh`, which supports **two modes**:

- **Env-driven mode (recommended)**  
  You do **not** pass any extra args after the image name. The entrypoint reads environment variables (from `--env-file` or `-e`), converts them to flags, and runs `reset-sidecar-four`.

- **Raw CLI mode**  
  You pass one or more flags after the image name. In that case, the entrypoint skips env → flag mapping and directly executes:

  ```
  reset-sidecar-four "$@"
  ```

Important:

- If you want to use env vars, **do not** put any flags after the image name.  
- If you put flags after the image name, only those flags apply; env vars are ignored by the entrypoint.

---

## ⚙️ Environment variables → flags

In **env-driven mode**, these env vars are translated to the corresponding Go flags. Empty values simply do not produce a flag.

| Env var                             | Flag                               | Default                                      | Description                                                              |
|-------------------------------------|------------------------------------|----------------------------------------------|--------------------------------------------------------------------------|
| `TARGETS`                           | `--targets`                        | *(required)*                                 | Comma-separated Prometheus targets (host:port or full URLs)             |
| `METRICS`                           | `--metrics`                        | *(required)*                                 | Comma-separated counter metrics to track                                |
| `METRICS_PATH`                      | `--metrics-path`                   | `/metrics`                                   | Path to scrape if targets are host:port                                 |
| `PASSTHROUGH_LABELS`                | `--passthrough-labels`             | *(none)*                                     | Comma-separated labels to preserve from scraped samples                 |
| `LISTEN_ADDR`                       | `--listen-addr`                    | `:9110`                                      | Bind address for HTTP `/metrics` (expose sink); empty disables expose   |
| `OUTPUT_FILE`                       | `--output-file`                    | `/var/lib/reset-sidecar/reset_sidecar.jsonl` | JSONL output path for file sink                                         |
| `REMOTE_WRITE_URL`                  | `--remote-write-url`               | *(disabled)*                                 | Prometheus `remote_write` endpoint                                      |
| `REMOTE_WRITE_USER`                 | `--remote-write-user`              | *(none)*                                     | Basic auth username for remote write                                    |
| *(file-based)*                      | `--remote-write-pass`              | `/etc/reset-sidecar/remote_write_pass`       | Password read from file; see “Secrets (password)” below                 |
| *(file-based)*                      | `--remote-write-ca-file`           | `/etc/reset-sidecar/root-ca.pem` or `custom.ca` | CA file; see “TLS CA” below                                          |
| `REMOTE_WRITE_INSECURE_SKIP_VERIFY` | `--remote-write-insecure-skip-verify` | `false`                                   | `true` to skip TLS verification (not recommended)                       |
| `REMOTE_WRITE_SERVER_NAME`          | `--remote-write-server-name`       | *(none)*                                     | Override TLS SNI/ServerName for remote write                            |
| `SCRAPE_INTERVAL`                   | `--scrape-interval`                | `30s`                                        | Scrape frequency                                                        |
| `PUBLISH_INTERVAL`                  | `--publish-interval`               | `15m` (binary default)                       | Publish frequency                                                       |
| `TIMEZONE`                          | `--timezone`                       | `Local` (binary default)                     | Timezone for file sink timestamps                                      |
| `JOB`                               | `--job`                            | `sidecar_metrics` (binary default)           | Job label attached to emitted series                                   |
| `VERBOSE`                           | `--verbose`                        | `false`                                      | `true` to enable verbose logging                                       |
| `TLS_TARGETS_CA` | `--tls_targets_ca` | *(none)* | CA file path for verifying HTTPS scrape targets (optional) |
| `TLS_CERT`       | `--tls_cert`       | *(none)* | Client TLS certificate for scraping HTTPS targets (optional, for mTLS) |
| `TLS_KEY`        | `--tls_key`        | *(none)* | Client TLS key for scraping HTTPS targets (optional, for mTLS) |

> Pushgateway (`--pushgateway-url`, `--push-job`) and scrape basic auth (`--basic-auth-user`, `--basic-auth-pass`) are currently only available via raw CLI flags, not env vars.

---

## 🔐 Secrets (password)

The remote write password is provided via a file *inside* the container, not via env:

- Default path in the container: `/etc/reset-sidecar/remote_write_pass`  
- At startup, `entrypoint.sh` does:

  ```
  if [[ -f /etc/reset-sidecar/remote_write_pass ]]; then
    REMOTE_WRITE_PASS=$(cat /etc/reset-sidecar/remote_write_pass)
  fi
  ```

To override the password safely:

1. Create a file on the host containing **only** the password, e.g.:

   ```
   myS3cretPass
   ```

2. Mount it into the container:

   ```
   -v /host/path/remote_write_pass:/etc/reset-sidecar/remote_write_pass:ro
   ```

This avoids putting the password into `.env` or on the CLI. For interactive use, you can wrap `docker run` in a small shell script that uses `read -s` and writes the password to a temporary file which you mount at this path.

---

## 🔒 TLS CA (remote write)

The CA used for `remote_write` TLS is selected as:

1. If `/etc/reset-sidecar/custom.ca` exists in the container, use:

   ```
   --remote-write-ca-file=/etc/reset-sidecar/custom.ca
   ```

2. Otherwise, use the default:

   ```
   --remote-write-ca-file=/etc/reset-sidecar/root-ca.pem
   ```

To supply your own CA:

```
-v /host/path/custom.ca:/etc/reset-sidecar/custom.ca:ro
```

The binary then loads this CA file when establishing TLS to `REMOTE_WRITE_URL`.

Note: TLS/mTLS for scraping targets is configured separately via the `--tls_targets_ca`, `--tls_cert`, and `--tls_key` CLI flags (currently CLI-only). 


---

## 🧾 CLI flags and modes

The `reset-sidecar-four` binary accepts all standard flags as described above.

**Env-driven mode (no args after image name)**

- Entry point reads env vars.
- Builds the full flag list.
- Runs `reset-sidecar-four` with those flags.

Example:

```
docker run --rm \
  --env-file .env \
  -v /run_files/reset_sidecar.jsonl:/var/lib/reset-sidecar/reset_sidecar.jsonl \
  -p 9110:9110 \
  my-reset-sidecar:latest
```

**Raw CLI mode (args after image name)**

- Env → flag mapping is **skipped**.
- Only the explicit flags are passed through.

Useful raw flags:

| Flag        | Description                                                        |
|------------|--------------------------------------------------------------------|
| `--verbose` | Enables detailed logs (overrides any `VERBOSE` env setting).       |
| `--help`    | Shows Go binary help.                                              |

Example (raw CLI mode):

```
docker run --rm \
  -p 9110:9110 \
  my-reset-sidecar:latest \
  --targets="192.168.1.2:3031" \
  --metrics="log_metric_counter_a_b_ab" \
  --passthrough-labels="type" \
  --listen-addr=":9110" \
  --output-file="/var/lib/reset-sidecar/reset_sidecar.jsonl" \
  --verbose
```

**Important:** if you want to use envs *and* tweak a few values, stay in env mode and override via `-e` instead of adding CLI flags after the image name:

```
docker run --rm \
  --env-file .env \
  -e TARGETS="192.168.1.2:3031" \
  -e METRICS="log_metric_counter_a_b_ab" \
  -e PASSTHROUGH_LABELS="type" \
  -v /run_files/reset_sidecar.jsonl:/var/lib/reset-sidecar/reset_sidecar.jsonl \
  -p 9110:9110 \
  my-reset-sidecar:latest
```

---

## 📦 Volumes

Recommended mounts:

| Path                         | Purpose                                             | Required |
|------------------------------|-----------------------------------------------------|----------|
| `/var/lib/reset-sidecar`     | Persists file sink output (`--output-file`)        | ✅       |
| `/var/log/reset-sidecar`     | Optional: entrypoint/app logs                      | optional |
| `/etc/reset-sidecar`         | Optional: configs, CA files, and `remote_write_pass` | optional |

Examples:

- Persist file sink output:

  ```
  -v /run_files/reset_sidecar.jsonl:/var/lib/reset-sidecar/reset_sidecar.jsonl
  ```

- Override remote write password:

  ```
  -v /host/path/remote_write_pass:/etc/reset-sidecar/remote_write_pass:ro
  ```

- Provide a custom CA:

  ```
  -v /host/path/custom.ca:/etc/reset-sidecar/custom.ca:ro
  ```

---

## 🌐 Ports

By default, if `LISTEN_ADDR` (or `--listen-addr`) is set to `:9110`, the container exposes `/metrics` on port `9110`.

| Port   | Description                            |
|--------|----------------------------------------|
| `9110` | HTTP `/metrics` endpoint (expose sink) |

To expose on the host:

```
-p 9110:9110
```

---

## 🪶 Example `.env` file

```
TARGETS=192.168.1.2:3031
METRICS=log_metric_counter_a_b_ab
PASSTHROUGH_LABELS=type
LISTEN_ADDR=:9110
OUTPUT_FILE=/var/lib/reset-sidecar/reset_sidecar.jsonl
TIMEZONE=Asia/Tehran
PUBLISH_INTERVAL=60s
SCRAPE_INTERVAL=30s
JOB=reset-sidecar
VERBOSE=false
REMOTE_WRITE_URL=
REMOTE_WRITE_USER=
REMOTE_WRITE_INSECURE_SKIP_VERIFY=false
REMOTE_WRITE_SERVER_NAME=
```

---

## 🔍 Example run (env-driven with secrets and CA)

```
docker run --rm \
  --env-file .env \
  -v /run_files/reset_sidecar.jsonl:/var/lib/reset-sidecar/reset_sidecar.jsonl \
  -v /host/path/remote_write_pass:/etc/reset-sidecar/remote_write_pass:ro \
  -v /host/path/custom.ca:/etc/reset-sidecar/custom.ca:ro \
  -p 9110:9110 \
  my-reset-sidecar:latest
```

---

## 📘 Notes

- Sinks are enabled purely by flags:
  - `--listen-addr` → expose sink.
  - `--output-file` → file sink.
  - `--remote-write-url` → remote_write sink.
- Counter resets trigger an immediate publish to all active sinks.
- The file sink writes one JSON line per metric state snapshot.
- The sidecar keeps state in memory; persistence depends on mounted volumes (e.g. file sink output).


### Some side note
since I wanted to use the resulted build go image also in a debian vm, I'd set two things:
1. the base image that I used for go is a debian 11 bullseye one before any rc one so it's go version is a bit lower (1.24.6-bullseye). this also resulted in changing go.mod file to `go 1.24.0`
2. I've created an export stage build phase that if used with the below docker build command exports the binary to the out folder
```
docker build \
  --build-arg GOPROXY=https://jfrog.partdp.ai/artifactory/api/go/go \
  --target export \
  --output type=local,dest=./out \
  .
```