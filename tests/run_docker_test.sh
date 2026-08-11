#!/usr/bin/env bash
set -e

export PATH="$PATH:/Applications/Docker.app/Contents/Resources/bin"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Dynamically fetch fastest live Russian TCP OpenVPN server URL from vpnobratno.info
OVPN_URL="$("$PROJECT_ROOT/scripts/fetch_fastest_ovpn.sh" "${1:-$OVPN_URL}")"

echo "==> Today's Live OpenVPN URL: $OVPN_URL"

echo "==> Building Docker image for greentunnelRS tests..."
docker build --build-arg OVPN_URL="$OVPN_URL" -t greentunnel-test -f "$SCRIPT_DIR/Dockerfile" "$PROJECT_ROOT"

echo "==> Running greentunnelRS integration test in Docker..."
docker run --rm -e OVPN_URL="$OVPN_URL" --cap-add=NET_ADMIN --device=/dev/net/tun greentunnel-test
