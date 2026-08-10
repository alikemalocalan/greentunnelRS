# ==============================================================================
# Stage 1: Build greentunnelRS Rust binary
# ==============================================================================
FROM rust:latest AS builder

WORKDIR /usr/src/greentunnelRS

# Copy Cargo manifests
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs to build dependencies and leverage Docker layer caching
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src

# Copy real source code and build final binary
COPY src ./src
RUN touch src/main.rs && cargo build --release

# ==============================================================================
# Stage 2: Integration Test Runner Environment (OpenVPN + Proxy + Curl)
# ==============================================================================
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install OpenVPN, curl, ca-certificates, and networking utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    openvpn \
    curl \
    ca-certificates \
    iproute2 \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy compiled greentunnelRS binary from builder stage
COPY --from=builder /usr/src/greentunnelRS/target/release/greentunnelRS /usr/local/bin/greentunnelRS

# Copy OpenVPN configuration file and test runner script
COPY tests/vpn541957482.opengw.net_ddns_udp.ovpn /app/openvpn.ovpn
COPY tests/run_test.sh /app/run_test.sh

RUN chmod +x /app/run_test.sh

# Environment variables
ENV OVPN_CONFIG=/app/openvpn.ovpn
ENV PROXY_PORT=8080

CMD ["/app/run_test.sh"]
