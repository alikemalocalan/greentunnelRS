#!/usr/bin/env bash
set -e

export PATH="$PATH:/Applications/Docker.app/Contents/Resources/bin"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "==> Building Docker image for greentunnelRS tests..."
docker build -t greentunnel-test -f "$SCRIPT_DIR/Dockerfile" "$PROJECT_ROOT"

echo "==> Running greentunnelRS integration test in Docker..."
docker run --rm --cap-add=NET_ADMIN --device=/dev/net/tun greentunnel-test
