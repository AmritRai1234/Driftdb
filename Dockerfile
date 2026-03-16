# ═══════════════════════════════════════════════════════════════
# DriftDB — Multi-stage Docker Build
# Final image: ~15 MB (alpine + 5.3 MB binary)
# ═══════════════════════════════════════════════════════════════

# Stage 1: Build
FROM rust:1.85-slim AS builder

WORKDIR /build
COPY . .

RUN apt-get update && apt-get install -y pkg-config libssl-dev && \
    cargo build --release && \
    strip target/release/driftdb

# Stage 2: Runtime (minimal alpine)
FROM alpine:3.21

RUN apk add --no-cache libgcc ca-certificates

COPY --from=builder /build/target/release/driftdb /usr/local/bin/driftdb

# Data directory
RUN mkdir -p /data /backups
VOLUME ["/data", "/backups"]

# Expose ports: WebSocket (9210), REST API (9211)
EXPOSE 9210 9211

# Health check via REST API
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD wget -qO- http://localhost:9211/health || exit 1

# Default: start server with REST API, bind to all interfaces
ENTRYPOINT ["driftdb"]
CMD ["--serve", "--rest", "--bind", "0.0.0.0", \
     "--data-dir", "/data"]
