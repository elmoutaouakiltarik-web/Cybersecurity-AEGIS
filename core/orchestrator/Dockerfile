FROM golang:1.22-alpine AS build

WORKDIR /src

# Cache dependencies first.
COPY go.mod go.sum ./
RUN go mod download

# Source.
COPY . .

# Build only (tests live alongside but require the full repo layout). Use
# -trimpath for reproducibility and strip symbols for size.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" \
    -o /out/cybersecurity-aegis-orchestrator .

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata curl \
 && adduser -D -H -u 10001 aegis \
 && mkdir -p /data /reports \
 && chown -R aegis:aegis /data /reports

USER aegis
WORKDIR /app

COPY --from=build /out/cybersecurity-aegis-orchestrator /app/orchestrator

ENV AEGIS_BIND_ADDR=0.0.0.0:8080 \
    AEGIS_EVENT_STORE=/data/events.jsonl \
    AEGIS_LOG_LEVEL=INFO

EXPOSE 8080

HEALTHCHECK --interval=20s --timeout=4s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/app/orchestrator"]
