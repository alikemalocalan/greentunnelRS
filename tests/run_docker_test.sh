#!/usr/bin/env bash
set -e

export PATH="$PATH:/Applications/Docker.app/Contents/Resources/bin"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Dynamically fetch today's active Russian OpenVPN server URL from vpnobratno.info if OVPN_URL is not explicitly passed
if [ -z "$OVPN_URL" ] && [ -z "$1" ]; then
    echo "==> Fetching today's live Russian OpenVPN server URL from vpnobratno.info..."
    HTML_LIST=$(curl -s --connect-timeout 8 https://vpnobratno.info/russia_server_list_en.html || echo "")
    MOSCOW_URL=$(echo "$HTML_LIST" | grep -B2 -A10 "Moscow" | grep -o 'href="[^"]*udp\.ovpn"' | head -n 1 | cut -d'"' -f2 || echo "")
    FIRST_URL=$(echo "$HTML_LIST" | grep -o 'href="[^"]*udp\.ovpn"' | head -n 1 | cut -d'"' -f2 || echo "")
    
    if [ -n "$MOSCOW_URL" ]; then
        OVPN_URL="$MOSCOW_URL"
    elif [ -n "$FIRST_URL" ]; then
        OVPN_URL="$FIRST_URL"
    else
        echo "Error: Failed to fetch live OpenVPN URL from vpnobratno.info"
        exit 1
    fi
else
    OVPN_URL="${1:-$OVPN_URL}"
fi

echo "==> Today's Live OpenVPN URL: $OVPN_URL"

echo "==> Building Docker image for greentunnelRS tests..."
docker build --build-arg OVPN_URL="$OVPN_URL" -t greentunnel-test -f "$SCRIPT_DIR/Dockerfile" "$PROJECT_ROOT"

echo "==> Running greentunnelRS integration test in Docker..."
docker run --rm -e OVPN_URL="$OVPN_URL" --cap-add=NET_ADMIN --device=/dev/net/tun greentunnel-test
