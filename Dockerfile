FROM artnexus.partdp.ir/golang:1.24.6-bullseye AS builder

WORKDIR /usr/src/app

ARG GOPROXY="https://jfrog.partdp.ai/artifactory/api/go/go"
ENV GOPROXY=${GOPROXY},direct 
ENV GOSUMDB=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64

COPY go.mod go.sum main.go ./
RUN go mod download && go mod verify

COPY . .
RUN go build -ldflags="-s -w" -v -o /usr/local/bin/reset-sidecar-four ./...

### 2nd build
FROM artnexus.partdp.ir/debian:bullseye-slim

RUN groupadd --system --gid 1141 appuser \
    && useradd --system --uid 1141 --gid 1141 --home /nonexistent --no-create-home --shell /sbin/nologin appuser


RUN mkdir -p /etc/reset-sidecar /var/log/reset-sidecar /var/lib/reset-sidecar \
    && chown appuser:appuser /etc/reset-sidecar /var/log/reset-sidecar /var/lib/reset-sidecar

COPY --from=builder --chown=appuser:appuser /usr/local/bin/reset-sidecar-four /usr/local/bin/
COPY --from=builder --chown=appuser:appuser /usr/src/app/root-ca.pem /etc/reset-sidecar/root-ca.pem
# COPY --from=builder --chown=appuser:appuser /usr/src/app/remote_write_pass /etc/reset-sidecar/remote_write_pass

COPY --chown=appuser:appuser entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 9110
USER appuser
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD []