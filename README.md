# GreenTunnel Rust CLI

High-performance, lightweight anti-censorship DPI bypass HTTP/HTTPS proxy written in Rust with zero GUI overhead — designed for Linux servers, macOS, Windows, and OpenWrt routers.

---

## Features

- ⚡ **SNI-Targeted Fragmentation:** Parses TLS ClientHello binary records and splits SNI hostname at the midpoint to bypass Deep Packet Inspection (DPI).
- 🔒 **TLS Record Layer Fragmentation:** Performs Layer 5 TLS record splitting.
- ⏱️ **Inter-Fragment Delay:** Introduces a 1–30ms timing gap between TLS records to trigger DPI reassembly timeouts (e.g. TSPU / Iran DPI).
- 🛡️ **Aggressive Mode (Connection Padding):** Pads small TLS ClientHello records to 512 bytes (RFC 7685) to frustrate size-based fingerprinting.
- 🌐 **DNS-over-HTTPS (DoH):** Queries Google DoH with in-memory caching to bypass DNS poisoning.
- 🚀 **Ultra-Lightweight & Fast:** Uses `tokio` async runtime, uses minimal RAM (<10 MB), perfect for embedded OpenWrt routers.

---

## Command Line Options / Parameters

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--port` | `-p` | `8080` | Local port for the proxy server to listen on. |
| `--bind` | `-b` | `127.0.0.1` | IP address to bind (`0.0.0.0` to allow LAN/router clients). |
| `--aggressive` | `-a` | `false` | Enables **Aggressive Mode** (proportional TLS ClientHello padding per RFC 7685). |
| `--disorder` | `-D` | `false` | Enables **TCP Disorder Mode** (sends TLS Record 2 before Record 1 to defeat stateful DPI reassembly). |
| `--fake-ttl` | `-F` | `0` | Injects fake ClientHello with low socket TTL to mislead DPI middleboxes (0 = disabled). |
| `--fake-sni` | - | `google.com` | Benign domain name used for fake ClientHello injection. |
| `--window-shrink` | `-W` | `0` | Restricts TCP socket buffer window size to force micro-segmentation (0 = disabled). |
| `--doh-url` | `-d` | `https://dns.google/resolve` | DoH (DNS-over-HTTPS) provider endpoint URL. |
| `--verbose` | `-v` | `false` | Enables verbose debug log output. |
| `--help` | `-h` | - | Prints help and parameter information. |
| `--version` | `-V` | - | Prints version information. |

### Parameter Details & Usage Scenarios

- **`-a, --aggressive` (Aggressive Mode)**:  
  Adds proportional TLS ClientHello padding using RFC 7685 Connection Padding. This prevents DPI systems (such as TSPU in Russia, Iran DPI, etc.) from identifying and blocking proxy connections using ClientHello packet size fingerprinting.

- **`-D, --disorder` (TCP Disorder Mode)**:  
  Transmits TLS Record 2 (containing trailing handshake data) *before* TLS Record 1 (containing the SNI split). Confuses stateful DPI reassembly engines while the target server's OS TCP stack correctly re-assembles the stream.

- **`-F, --fake-ttl <TTL>` (Fake Packet Injection)**:  
  Injects a fake `ClientHello` payload for `--fake-sni` (e.g. `google.com`) with a low TTL (Time-To-Live). The fake packet reaches and misleads the ISP DPI box, while expiring before reaching the target server.

- **`-W, --window-shrink <BYTES>` (TCP Window Shrinking)**:  
  Restricts socket buffer window size to force OS-level TCP micro-segmentation.

- **`-b, --bind <IP>`**:  
  Use `127.0.0.1` (default) for localhost proxying. Set to `0.0.0.0` when deploying on a home router (OpenWrt) or server to serve all clients on your local network.

- **`-d, --doh-url <URL>`**:  
  Configures the DNS-over-HTTPS resolver URL (e.g. `https://dns.google/resolve` or `https://cloudflare-dns.com/dns-query`) to bypass DNS poisoning and censorship.

- **`-v, --verbose`**:  
  Enables detailed debug level logs, useful for inspecting connection handling and DPI bypass operations in real-time.

---

## Build & Run

### 1. Build locally
```bash
cargo build --release
```

### 2. Usage Examples

```bash
# Basic run (default port 8080 on 127.0.0.1)
./target/release/greentunnelRS

# Run with Aggressive Mode enabled (TLS ClientHello Padding)
./target/release/greentunnelRS --aggressive

# Run with custom port and Aggressive Mode
./target/release/greentunnelRS --port 9090 --aggressive

# Run with Aggressive Mode, custom port, and verbose logging
./target/release/greentunnelRS --port 8080 --aggressive --verbose

# Run on OpenWrt / Router (listen on all network interfaces with custom DoH provider)
./target/release/greentunnelRS --bind 0.0.0.0 --port 8080 --aggressive --doh-url "https://cloudflare-dns.com/dns-query"
```

---

## Installing & Running on OpenWrt Routers

You can download and run the prebuilt statically-linked binary directly on your 64-bit ARM OpenWrt router without installing any extra runtime dependencies:

### Quick Start via SSH on OpenWrt

```bash
# 1. Download the prebuilt 64-bit ARM binary from GitHub Releases
wget https://github.com/alikemalocalan/greentunnelRS/releases/latest/download/greentunnelRS-openwrt-aarch64

# 2. Make it executable
chmod +x greentunnelRS-openwrt-aarch64

# 3. Run the proxy server (listening on 0.0.0.0 for LAN clients with Aggressive Mode)
./greentunnelRS-openwrt-aarch64 --bind 0.0.0.0 --port 8080 --aggressive
```

---

## Cross-Compiling for OpenWrt Routers

On macOS/Linux, you can cross-compile using `cross` (Docker-backed Rust cross-compiler):

```bash
cargo install cross --git https://github.com/cross-rs/cross

# Build for 64-bit ARM OpenWrt
cross build --release --target aarch64-unknown-linux-musl
```

*Note: If you push a tag/release to GitHub, the included GitHub Action automatically builds and attaches the `aarch64-unknown-linux-musl` binary to your release page.*