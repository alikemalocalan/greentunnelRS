#!/usr/bin/env bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
RESET='\033[0m'

LOG_DIR="/var/log"
OPENVPN_LOG="$LOG_DIR/openvpn.log"
PROXY_LOG="$LOG_DIR/greentunnel.log"
OVPN_CONFIG="${OVPN_CONFIG:-/app/openvpn.ovpn}"
PROXY_PORT="${PROXY_PORT:-8080}"

echo -e "${CYAN}====================================================${RESET}"
echo -e "${CYAN}   greentunnelRS — Russia Proxy Mode               ${RESET}"
echo -e "${CYAN}   Listening on 0.0.0.0:${PROXY_PORT}                    ${RESET}"
echo -e "${CYAN}====================================================${RESET}"

# 1. TUN device
if [ ! -c /dev/net/tun ]; then
    echo -e "${YELLOW}[+] Creating /dev/net/tun...${RESET}"
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
    chmod 600 /dev/net/tun
fi

# 2. Download OVPN config if OVPN_URL is provided
if [ -n "$OVPN_URL" ]; then
    echo -e "${YELLOW}[+] Downloading OpenVPN config from:${RESET}"
    echo -e "    ${CYAN}$OVPN_URL${RESET}"
    if curl -s -f --connect-timeout 10 "$OVPN_URL" -o /app/openvpn.ovpn; then
        echo -e "    ${GREEN}Downloaded successfully.${RESET}"
    else
        echo -e "    ${YELLOW}Download failed, using baked-in config.${RESET}"
    fi
fi

# 3. Start OpenVPN
echo -e "${YELLOW}[+] Starting OpenVPN...${RESET}"
openvpn --config "$OVPN_CONFIG" --log "$OPENVPN_LOG" --daemon

# Cleanup on exit
cleanup() {
    echo -e "\n${YELLOW}[+] Shutting down...${RESET}"
    kill "$PROXY_PID" 2>/dev/null || true
    pkill openvpn 2>/dev/null || true
}
trap cleanup EXIT SIGINT SIGTERM

# 4. Wait for VPN tunnel
echo -n "    Waiting for tun0 interface"
WAIT=0
while [ $WAIT -lt 30 ]; do
    if ip link show tun0 >/dev/null 2>&1 || grep -q "Initialization Sequence Completed" "$OPENVPN_LOG" 2>/dev/null; then
        break
    fi
    sleep 1
    WAIT=$((WAIT + 1))
    echo -n "."
done
echo ""

if ip link show tun0 >/dev/null 2>&1 || grep -q "Initialization Sequence Completed" "$OPENVPN_LOG" 2>/dev/null; then
    echo -e "    ${GREEN}VPN connected!${RESET}"

    # Switch to Russian DNS over the VPN tunnel.
    # Yandex DNS (77.88.8.8 / 77.88.8.1) is native Russian and reliably reachable
    # from a Russian IP. AdGuard (94.140.14.14) is a fast global fallback.
    echo "nameserver 77.88.8.8"  > /etc/resolv.conf
    echo "nameserver 77.88.8.1" >> /etc/resolv.conf
    echo "nameserver 94.140.14.14" >> /etc/resolv.conf
    echo -e "    ${CYAN}DNS → Yandex DNS (77.88.8.8) via VPN tunnel${RESET}"

    # Show Russian public IP
    IP_INFO=$(curl -s --connect-timeout 8 http://ip-api.com/json 2>/dev/null || echo "")
    if [ -n "$IP_INFO" ]; then
        PUB_IP=$(echo "$IP_INFO" | grep -o '"query": "[^"]*' | cut -d'"' -f4)
        COUNTRY=$(echo "$IP_INFO" | grep -o '"country": "[^"]*' | cut -d'"' -f4)
        echo -e "    ${GREEN}Public IP : ${CYAN}${PUB_IP:-?}${RESET}"
        echo -e "    ${GREEN}Country   : ${CYAN}${COUNTRY:-?}${RESET}"
    fi
else
    echo -e "    ${YELLOW}VPN timeout — continuing anyway (direct connection).${RESET}"
    tail -n 10 "$OPENVPN_LOG" 2>/dev/null || true
fi

# 5. Start greentunnelRS proxy bound to all interfaces (host-accessible)
echo -e "${YELLOW}[+] Starting greentunnelRS proxy on 0.0.0.0:${PROXY_PORT}...${RESET}"
greentunnelRS --port "$PROXY_PORT" --bind 0.0.0.0 --dns-addr 77.88.8.8:53 --no-tls-padding --no-post-quantum >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

sleep 2

if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo -e "${RED}[!] greentunnelRS failed to start:${RESET}"
    cat "$PROXY_LOG"
    exit 1
fi

echo -e "${GREEN}[+] Proxy is up (PID: $PROXY_PID)${RESET}"
echo -e ""
echo -e "${CYAN}  Firefox Manual Proxy Settings:${RESET}"
echo -e "${CYAN}    HTTP Proxy : 127.0.0.1${RESET}"
echo -e "${CYAN}    Port       : ${PROXY_PORT}${RESET}"
echo -e ""
echo -e "${YELLOW}  Press Ctrl+C to stop.${RESET}"
echo -e "${CYAN}====================================================${RESET}"

# Keep running — tail proxy log to stdout
tail -f "$PROXY_LOG" &
wait "$PROXY_PID"
