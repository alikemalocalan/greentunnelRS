#!/usr/bin/env bash
# ============================================================
# run_russia_proxy.sh
#
# Runs greentunnelRS proxy through a Russian VPN inside Docker.
# Exposes port 8080 to the host — configure Firefox to use
# 127.0.0.1:8080 as an HTTP proxy to browse via Russia.
#
# Usage: ./run_russia_proxy.sh [OVPN_URL]
# ============================================================
set -e

export PATH="$PATH:/Applications/Docker.app/Contents/Resources/bin"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_PORT="${PROXY_PORT:-8080}"
IMAGE_NAME="greentunnel-russia-proxy"

# ---- Select fastest TCP OVPN server by advertised speed ---------------
OVPN_URL="$("$SCRIPT_DIR/scripts/fetch_fastest_ovpn.sh" "${1:-$OVPN_URL}")"

echo "==> Using OpenVPN URL: $OVPN_URL"

# ---- Build Docker image -----------------------------------------------
echo "==> Building Docker image..."
docker build \
    --build-arg OVPN_URL="$OVPN_URL" \
    -t "$IMAGE_NAME" \
    -f "$SCRIPT_DIR/tests/Dockerfile.proxy" \
    "$SCRIPT_DIR"

# ---- Run proxy container ----------------------------------------------
echo ""
echo "==> Starting container..."
echo "    Once the proxy is ready, configure Firefox:"
echo "    Settings > Network Settings > Manual Proxy"
echo "      HTTP Proxy : 127.0.0.1"
echo "      Port       : ${PROXY_PORT}"
echo ""
echo "    Press Ctrl+C to stop."
echo ""

# ---- Stop any container already holding port 8080 -------------------------
EXISTING=$(docker ps -q --filter "publish=${PROXY_PORT}" 2>/dev/null)
if [ -n "$EXISTING" ]; then
    echo "==> Stopping existing container on port ${PROXY_PORT}..."
    docker rm -f "$EXISTING" >/dev/null
fi

docker run --rm \
    --cap-add=NET_ADMIN \
    --device=/dev/net/tun \
    -p "${PROXY_PORT}:${PROXY_PORT}" \
    -e OVPN_URL="$OVPN_URL" \
    -e PROXY_PORT="$PROXY_PORT" \
    "$IMAGE_NAME"
