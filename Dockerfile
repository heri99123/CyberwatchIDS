# Multi-stage Dockerfile for CyberWatch IDS Rust Backend
# Stage 1: Build Rust binary
FROM rust:1.82-bookworm AS builder

WORKDIR /build

# Copy Cargo files first for dependency caching
COPY backend/Cargo.toml backend/Cargo.lock* ./
# Cargo.toml declares readme = "../README.md"; make it resolvable in the image
COPY README.md /README.md

# Create a dummy src/main.rs to build dependencies first
RUN mkdir -p src/routes && \
    echo "fn main() {}" > src/main.rs && \
    echo "" > src/routes/mod.rs && \
    cargo build --release || true

# Copy actual source code (env is injected at runtime, never baked into the image)
COPY backend/src/ src/

# Build the actual binary
RUN cargo build --release

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/target/release/cyberwatch-ids /app/cyberwatch-ids

# Copy Vue frontend dist (built by the frontend CI job)
COPY dist/ /app/dist/

# Ensure writable data directory (init_database() creates parent dirs + schema)
RUN mkdir -p /app/data

ENV PORT=8421
ENV DATABASE_PATH=/app/data/cve-database.db
ENV RUST_LOG=info,cyberwatch=debug

EXPOSE 8421

CMD ["/app/cyberwatch-ids"]
