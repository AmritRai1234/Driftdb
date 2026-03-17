# ═══════════════════════════════════════════════════════════════
# DriftDB — Multi-stage Docker Build
# Final image: ~15 MB (alpine + 5.3 MB binary)
# ═══════════════════════════════════════════════════════════════

# Stage 1: Build
FROM rust:bookworm AS builder

WORKDIR /build
COPY . .

RUN apt-get update && apt-get install -y pkg-config libssl-dev && \
    cargo build --release && \
    strip target/release/driftdb

# Stage 2: Runtime (Debian slim — matches glibc from builder)
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/driftdb /usr/local/bin/driftdb

# Data directory
RUN mkdir -p /data /backups
VOLUME ["/data", "/backups"]

# Expose ports: WebSocket (9210), REST API + Dashboard (9211)
EXPOSE 9210 9211

# Health check via REST API
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD wget -qO- http://localhost:9211/health || exit 1

# Default: start server with REST API + Dashboard, bind to all interfaces
# Use shell form so $DRIFT_TOKEN env var is expanded at runtime
CMD driftdb --serve --rest --bind 0.0.0.0 --data-dir /data \
    ${DRIFT_TOKEN:+--ws-token $DRIFT_TOKEN}
