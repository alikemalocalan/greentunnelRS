#!/usr/bin/env bash
# ============================================================
# fetch_fastest_ovpn.sh
#
# Fetches Russian OpenVPN server list from vpnobratno.info,
# sorts by advertised speed (descending), probes reachability,
# and outputs the fastest working TCP .ovpn server URL.
#
# Usage:
#   ./scripts/fetch_fastest_ovpn.sh [CUSTOM_URL]
# ============================================================
set -e

PASSED_URL="${1:-$OVPN_URL}"
if [ -n "$PASSED_URL" ]; then
    echo "$PASSED_URL"
    exit 0
fi

echo "==> Fetching Russian OpenVPN server list from vpnobratno.info..." >&2
HTML_LIST=$(curl -s --connect-timeout 8 https://vpnobratno.info/russia_server_list_en.html || echo "")

if [ -z "$HTML_LIST" ]; then
    echo "Error: Could not fetch server list from vpnobratno.info" >&2
    exit 1
fi

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
    echo "Error: No TCP OpenVPN servers found on vpnobratno.info" >&2
    exit 1
fi

echo "==> Probing fastest TCP servers (speed-sorted)..." >&2
FASTEST_URL=""
while IFS= read -r url; do
    [ -z "$url" ] && continue
    if curl -sf --head --connect-timeout 4 "$url" -o /dev/null 2>/dev/null; then
        FASTEST_URL="$url"
        echo "    ✓ Selected: $url" >&2
        break
    else
        echo "    ✗ Unreachable: $url" >&2
    fi
done <<< "$SORTED_URLS"

if [ -z "$FASTEST_URL" ]; then
    echo "Error: No reachable TCP OpenVPN server found" >&2
    exit 1
fi

echo "$FASTEST_URL"
