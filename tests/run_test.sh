#!/usr/bin/env bash
set -e

# Color definitions
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0;31m' # No Color
RESET='\033[0m'

LOG_DIR="/var/log"
OPENVPN_LOG="$LOG_DIR/openvpn.log"
PROXY_LOG="$LOG_DIR/greentunnel.log"
OVPN_CONFIG="${OVPN_CONFIG:-/app/openvpn.ovpn}"
PROXY_PORT="${PROXY_PORT:-8080}"

echo -e "${CYAN}====================================================${RESET}"
echo -e "${CYAN}   GreenTunnel Rust - Docker Integration Test Suite ${RESET}"
echo -e "${CYAN}====================================================${RESET}"

# 1. Setup TUN device for OpenVPN if missing inside Docker container
if [ ! -c /dev/net/tun ]; then
    echo -e "${YELLOW}[+] Creating /dev/net/tun character device...${RESET}"
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
    chmod 600 /dev/net/tun
fi

# 2. Download OpenVPN configuration directly to /app/openvpn.ovpn if OVPN_URL is specified
if [ -n "$OVPN_URL" ]; then
    echo -e "${YELLOW}[+] Downloading OpenVPN configuration from OVPN_URL...${RESET}"
    echo -e "   ${CYAN}$OVPN_URL${RESET}"
    if curl -s -f --connect-timeout 10 "$OVPN_URL" -o /app/openvpn.ovpn; then
        echo -e "   ${GREEN}Successfully downloaded OpenVPN config to /app/openvpn.ovpn!${RESET}"
    else
        echo -e "   ${YELLOW}Download failed, using existing /app/openvpn.ovpn${RESET}"
    fi
fi

# 3. Start OpenVPN in background
echo -e "${YELLOW}[+] Starting OpenVPN connection with $(basename "$OVPN_CONFIG")...${RESET}"
openvpn --config "$OVPN_CONFIG" --log "$OPENVPN_LOG" &
OPENVPN_PID=$!

cleanup() {
    echo -e "\n${YELLOW}[+] Cleaning up background services...${RESET}"
    if [ -n "$PROXY_PID" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
        kill "$PROXY_PID" 2>/dev/null || true
    fi
    if [ -n "$OPENVPN_PID" ] && kill -0 "$OPENVPN_PID" 2>/dev/null; then
        kill "$OPENVPN_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Wait for OpenVPN tun0 interface to come up
echo -n "   Waiting for OpenVPN tunnel (tun0)... "
WAIT_COUNT=0
MAX_WAIT=20
VPN_CONNECTED=false

while [ $WAIT_COUNT -lt $MAX_WAIT ]; do
    if ip link show tun0 >/dev/null 2>&1 || grep -q "Initialization Sequence Completed" "$OPENVPN_LOG" 2>/dev/null; then
        VPN_CONNECTED=true
        break
    fi
    sleep 1
    WAIT_COUNT=$((WAIT_COUNT + 1))
    echo -n "."
done

if [ "$VPN_CONNECTED" = true ]; then
    echo -e " ${GREEN}CONNECTED!${RESET}"
else
    echo -e " ${YELLOW}TIMED OUT (Proceeding with direct connection test)...${RESET}"
    echo "--- OpenVPN Log tail ---"
    tail -n 15 "$OPENVPN_LOG" 2>/dev/null || true
    echo "------------------------"
fi

# 3. Start greentunnelRS proxy server
echo -e "${YELLOW}[+] Launching greentunnelRS proxy on port $PROXY_PORT...${RESET}"
greentunnelRS --port "$PROXY_PORT" --bind 127.0.0.1 --dns-addr 8.8.8.8:53 --verbose > "$PROXY_LOG" 2>&1 &
PROXY_PID=$!

sleep 2

if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo -e "${RED}[!] Error: greentunnelRS failed to start! (Exit log below)${RESET}"
    echo "------------------ PROXY LOG ------------------"
    cat "$PROXY_LOG"
    echo "-----------------------------------------------"
    exit 1
fi

echo -e "${GREEN}[+] greentunnelRS is running (PID: $PROXY_PID)${RESET}"

# Fetch public IP and Geolocation via greentunnelRS proxy
echo -e "${YELLOW}[+] Verifying Public IP & Geolocation via VPN + greentunnelRS Proxy...${RESET}"
IP_INFO=$(curl -s -x "http://127.0.0.1:$PROXY_PORT" --connect-timeout 8 http://ip-api.com/json 2>/dev/null || curl -s -x "http://127.0.0.1:$PROXY_PORT" --connect-timeout 8 https://ipinfo.io/json 2>/dev/null || echo "")
if [ -n "$IP_INFO" ]; then
    PUB_IP=$(echo "$IP_INFO" | grep -o '"query": "[^"]*' | cut -d'"' -f4)
    [ -z "$PUB_IP" ] && PUB_IP=$(echo "$IP_INFO" | grep -o '"ip": "[^"]*' | cut -d'"' -f4)
    COUNTRY=$(echo "$IP_INFO" | grep -o '"country": "[^"]*' | cut -d'"' -f4)
    [ -z "$COUNTRY" ] && COUNTRY=$(echo "$IP_INFO" | grep -o '"countryCode": "[^"]*' | cut -d'"' -f4)
    ORG=$(echo "$IP_INFO" | grep -o '"isp": "[^"]*' | cut -d'"' -f4)
    [ -z "$ORG" ] && ORG=$(echo "$IP_INFO" | grep -o '"org": "[^"]*' | cut -d'"' -f4)
    echo -e "   ${GREEN}Public IP : ${CYAN}${PUB_IP:-Unknown}${RESET}"
    echo -e "   ${GREEN}Country   : ${CYAN}${COUNTRY:-Unknown}${RESET}"
    echo -e "   ${GREEN}ISP / Org : ${CYAN}${ORG:-Unknown}${RESET}"
fi

# 4. Target URLs to test (Instagram/Meta excluded due to ISP IP-level blackholing in Russia)
TARGET_URLS=(
    "https://www.google.com"
    "https://x.com"
    "https://signal.org"
    "https://www.youtube.com"
    "https://www.wikipedia.org"
)

TOTAL_TESTS=${#TARGET_URLS[@]}
PASSED_TESTS=0

echo -e "\n${CYAN}--- Testing HTTP/HTTPS Connectivity via greentunnelRS Proxy (127.0.0.1:$PROXY_PORT) ---${RESET}\n"

printf "%-35s %-15s %-10s\n" "TARGET URL" "HTTP STATUS" "RESULT"
printf "%-35s %-15s %-10s\n" "-----------------------------------" "---------------" "----------"

for url in "${TARGET_URLS[@]}"; do
    # Run curl through greentunnelRS proxy
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -x "http://127.0.0.1:$PROXY_PORT" --connect-timeout 10 --max-time 15 "$url" 2>/dev/null || true)
    [ -z "$http_code" ] && http_code="000"

    if [[ "$http_code" =~ ^[23][0-9]{2}$ ]]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        printf "%-35s \033[0;32m%-15s\033[0m \033[0;32m%-10s\033[0m\n" "$url" "HTTP $http_code" "[ PASS ]"
    else
        printf "%-35s \033[0;31m%-15s\033[0m \033[0;31m%-10s\033[0m\n" "$url" "HTTP ${http_code:-000}" "[ FAIL ]"
    fi
done

echo -e "\n${CYAN}====================================================${RESET}"
echo -e " Test Results: ${GREEN}$PASSED_TESTS / $TOTAL_TESTS Passed${RESET}"
echo -e "${CYAN}====================================================${RESET}"

if [ $PASSED_TESTS -gt 0 ]; then
    echo -e "${GREEN}>>> greentunnelRS Proxy Integration Test Completed Successfully! <<<${RESET}"
    exit 0
else
    echo -e "${RED}[!] All proxy test requests failed. Inspecting proxy log:${RESET}"
    tail -n 20 "$PROXY_LOG"
    exit 1
fi
