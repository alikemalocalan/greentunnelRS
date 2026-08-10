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
if [ -z "$OVPN_URL" ] && [ -z "$1" ]; then
    echo "==> Fetching Russian OpenVPN server list from vpnobratno.info..."
    HTML_LIST=$(curl -s --connect-timeout 8 https://vpnobratno.info/russia_server_list_en.html || echo "")

    if [ -z "$HTML_LIST" ]; then
        echo "Error: Could not fetch server list from vpnobratno.info."
        exit 1
    fi

    # Parse (speed, tcp_url) pairs: for each TCP URL find the closest Speed Mb/s
    # value that appears before it in the HTML, then sort by speed descending.
    TMPPY=$(mktemp /tmp/parse_vpn.XXXXXX.py)
    cat > "$TMPPY" << 'PYEOF'
import re, sys
html = sys.stdin.read()
tcp_links  = [(m.start(), m.group(1)) for m in re.finditer(r'href="([^"]*ddns_tcp\.ovpn)"', html)]
speed_hits = [(m.start(), int(m.group(1))) for m in re.finditer(r'Speed (\d+) Mb/s', html)]
pairs = []
for link_pos, url in tcp_links:
    before = [(pos, spd) for pos, spd in speed_hits if pos < link_pos]
    speed  = before[-1][1] if before else 0
    pairs.append((speed, url))
pairs.sort(reverse=True)
for speed, url in pairs:
    print(url)
PYEOF
    SORTED_URLS=$(echo "$HTML_LIST" | python3 "$TMPPY")
    rm -f "$TMPPY"

    if [ -z "$SORTED_URLS" ]; then
        echo "Error: No TCP OpenVPN servers found on vpnobratno.info."
        exit 1
    fi

    echo "==> Probing fastest TCP servers (speed-sorted)..."
    OVPN_URL=""
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        if curl -sf --head --connect-timeout 4 "$url" -o /dev/null 2>/dev/null; then
            OVPN_URL="$url"
            echo "    ✓ Selected: $url"
            break
        else
            echo "    ✗ Unreachable: $url"
        fi
    done <<< "$SORTED_URLS"

    if [ -z "$OVPN_URL" ]; then
        echo "Error: No reachable TCP server found. Try again later or pass a URL manually."
        exit 1
    fi
else
    OVPN_URL="${1:-$OVPN_URL}"
fi

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
