# GreenTunnel Rust CLI

Ultra-fast, zero-dependency anti-censorship DPI bypass HTTP/HTTPS proxy written in Rust.  
Engineered for embedded OpenWrt routers (e.g. GL.iNet Beryl AX), Linux servers, macOS, and Windows. Operates at **Layer 4/7** with SNI midpoint record splitting, RFC 7685 ClientHello padding, and multi-core CPU scaling in an **ultra-small binary size (~748 KB)**.

---

## Features

- ⚡ **SNI-Targeted Fragmentation:** Parses TLS ClientHello binary records and splits SNI hostname at the midpoint to bypass Deep Packet Inspection (DPI).
- 🔒 **TLS Record Layer Fragmentation:** Performs Layer 5 TLS record splitting.
- ⏱️ **Inter-Fragment Delay:** Introduces a 1–30ms timing gap between TLS records to trigger DPI reassembly timeouts (e.g. TSPU / Iran DPI).
- 🛡️ **Aggressive Mode (Connection Padding):** Pads small TLS ClientHello records to 512 bytes (RFC 7685) to frustrate size-based fingerprinting.
- 🌐 **Zero-Dependency Local UDP DNS:** Queries local loopback (`127.0.0.1:53` / `dnscrypt-proxy`) with sub-millisecond (<0.2ms) response times and in-memory TTL caching.
- 🚀 **Ultra-Lightweight & Fast:** Built with `tokio` async runtime and Linux `SO_REUSEPORT` multi-core CPU worker pool, minimal RAM (<10 MB), and ultra-small binary size (~748 KB), perfect for OpenWrt routers (e.g. GL.iNet Beryl AX).

---

## Implementation & Impact Rating Table

| Feature / Evasion Method | Evasion Mechanism | Implementation Status | GoodbyeDPI Equiv. | TSPU Bypass Impact | Performance Overhead |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **SNI Midpoint Record Splitting** | Cuts TLS `ClientHello` inside hostname string across 2 TLS records. | ✅ Implemented | ✅ Available (`-s`) | 🔥 **Critical (High)** | ⚡ Negligible (<1ms) |
| **Zero-Dependency Local UDP DNS** | Queries local DNS (`127.0.0.1:53` / `dnscrypt-proxy`) with instant cache. | ✅ Implemented | ✅ Available (`--dns-addr`) | 🔥 **Critical (High)** | ⚡ Sub-millisecond (<0.2ms) |
| **Domain-Aware Meta Filter** | Skips TLS padding for Meta/Instagram to avoid C++ Fizz TLS drops. | ✅ Implemented | ❌ N/A (Global Rules) | 🔥 **Critical (High)** | ⚡ Zero |
| **Proportional TLS Padding** | Adds dynamic +32..128B RFC 7685 padding based on ClientHello length. | ✅ Implemented | ❌ Not Supported | 🔶 **High** | ⚡ Negligible |
| **Fast Inter-Fragment Delay (1-5ms)** | Triggers TSPU reassembly buffer timeout between TLS records. | ✅ Implemented | ❌ Not Supported | 🔶 **High** | ⏱️ 1–5ms handshake |
| **Linux SO_REUSEPORT Multi-Worker** | Distributes socket accept loops across all CPU cores on Linux/OpenWrt. | ✅ Implemented | ❌ N/A (Windows Only) | 🔶 **High** | ⚡ Max Throughput |
| **TCP_NODELAY Socket Tuning** | Flushes SNI split packets immediately, overriding OS Nagle delay. | ✅ Implemented | ❌ N/A (WinDivert Layer) | 🟡 **Medium** | ⚡ Improves latency |
| **Proxy Header Stripping** | Removes `Via`, `X-Forwarded-For`, `Proxy-Connection` headers. | ✅ Implemented | ✅ Available (`-h`) | 🟡 **Medium** | ⚡ Zero |
| **Out-of-Order (Disorder) TCP** | Sends TLS Record 2 before Record 1 to break stateful TSPU reassembly. | ✅ Implemented | ✅ Available (`-d`) | 🔶 **High** | ⚡ Negligible |
| **Fake Packet TTL Injection** | Sends fake benign `ClientHello` with low TTL to mislead TSPU. | ✅ Implemented | ✅ Available (`-f / --set-ttl`) | 🔶 **High** | ⏱️ +1 RTT |
| **TCP Window Size Shrinking** | Sets TCP socket buffer window size to force micro-segmentation. | ✅ Implemented | ✅ Available (`-w`) | 🟡 **Medium** | ⏱️ Minor handshake delay |
| **TCP Source Port Rotation** | Rotates client TCP port on socket connection to evade 4-tuple blackhole bans. | ✅ Implemented | ✅ Enabled by default (`-R`) | 🔥 **Critical (High)** | ⚡ Zero |
| **QUIC Alt-Svc Stripping** | Strips `Alt-Svc` headers to enforce TCP TLS 1.3 over censored QUIC UDP. | ✅ Implemented | ✅ Enabled by default (`-s`) | 🔥 **Critical (High)** | ⚡ Zero |
| **Post-Quantum TLS 1.3 (ML-KEM)** | Supports hybrid ML-KEM-768 Kyber KeyShare extensions to defeat quantum & PQC-aware DPI. | 🚧 *Planned (Roadmap)* | ❌ Not Supported | 🔥 **Critical (High)** | ⚡ Zero |
| **Dynamic JA4 Randomization** | Randomizes TLS ClientHello extension ordering to frustrate JA3/JA4 fingerprinting. | ✅ Implemented | ✅ Enabled by default (`-J`) | 🔶 **High** | ⚡ Zero |
| **UDP-over-TCP (UoT) Mode** | Encapsulates UDP frames inside length-prefixed TCP streams when UDP is blocked. | ❌ Skipped (Too complex) | ❌ Not Supported | 🔥 **Critical (High)** | ⚡ Negligible |
| **Active Probing Fallback Target** | Proxies unauthorized ISP scanner bot probes to a local web server (Nginx/404). | 🚧 *Planned (Roadmap)* | ❌ Not Supported | 🔶 **High** | ⚡ Zero |
| **TLS Extension Permutation** | Randomizes TLS extension ordering to prevent static client fingerprinting. | ✅ Implemented | ✅ Enabled by default (`-J`) | 🔶 **High** | ⚡ Zero |
| **DNS Type 65 Filtering** | Filters malicious DNS `HTTPS` (type 65) records injected by ISP DNS poisoning. | ✅ Implemented | ✅ Enabled by default (`-T`) | 🔶 **High** | ⚡ Zero |
| **Statistical Traffic Masking** | Transmits low-volume background noise to multiple CDN IPs to confuse flow frequency analyzers. | 🚧 *Planned (Roadmap)* | ❌ Not Supported | 🔶 **High** | ⏱️ <11 Kbps noise |
| **HTTP Header Case Mixing** | Randomizes case in HTTP headers (e.g. `hOsT:`) to break string matching. | ✅ Implemented | ✅ Enabled by default (`-m`) | 🟡 **Medium** | ⚡ Zero |
| **HTTP CONNECT Space Insertion** | Inserts extra spaces in CONNECT requests to confuse DPI regex splitters. | ✅ Implemented | ✅ Enabled by default (`-e`) | 🟡 **Medium** | ⚡ Zero |
| **FQDN Trailing Dot Obfuscation** | Appends trailing dot (`example.com.`) to break exact domain filters. | ✅ Implemented | ✅ Available (`-t`) | 🟡 **Medium** | ⚡ Zero |
| **Auto HTTPS Redirection (Port 80)** | Intercepts plaintext HTTP and issues 301 redirect to encrypted HTTPS. | 🚧 *Planned (Roadmap)* | ✅ Available (`-r`) | 🔶 **High** | ⚡ Faster handshake |
| **DNSCrypt Protocol Support** | Curve25519 authenticated UDP/TCP DNS resolution over Port 443 without TLS SNI. | 🚧 *Planned (Roadmap)* | ❌ N/A (External) | 🔶 **High** | ⏱️ +80-120KB binary |

---

## Architectural Comparison: greentunnelRS vs. GoodbyeDPI

| Architectural Aspect | GoodbyeDPI | greentunnelRS |
| :--- | :--- | :--- |
| **Operating Layer** | **Layer 3 / 4 (Network & Transport)** — Operates as a kernel-level packet filter (WinDivert driver). | **Layer 4 / 7 (Transport & Application)** — Operates as an intelligent user-space proxy server. |
| **OS Compatibility** | 🪟 **Windows Only** (requires WinDivert kernel driver). | 🐧 **Cross-Platform** (OpenWrt routers, Linux servers, macOS, Windows). |
| **TLS Protocol Awareness** | Reads raw TCP bytes without deep TLS record parsing. | Parses Layer 7 `ClientHello` structures, applies RFC 7685 padding, and cuts SNI hostnames dynamically. |
| **Domain-Specific Filtering** | Applies global packet manipulation rules to all TCP traffic. | Detects target domains (e.g., Meta/Instagram Fizz TLS bypass) and adjusts padding rules automatically. |
| **CPU Scaling** | Single-threaded packet interception via WinDivert driver loop. | Linux `SO_REUSEPORT` multi-worker pool scaling across all CPU cores (e.g., dual/quad-core OpenWrt routers). |
| **Setup Overhead** | Requires Administrator / Kernel Driver installation on Windows. | Zero driver installation; runs as a portable standalone binary (~748 KB). |

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
| `--dns-addr` | `-d` | `127.0.0.1:53` | DNS resolver server IP:port (`127.0.0.1:53` for local loopback / dnscrypt-proxy / dnsmasq). |
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

- **`-d, --dns-addr <IP:PORT>`**:  
  Configures local or remote UDP DNS resolver IP:port (e.g. `127.0.0.1:53` or `127.0.0.1:55` for dnscrypt-proxy) to bypass DNS poisoning and censorship.

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

# Run on OpenWrt / Router (listen on all network interfaces with local dnscrypt-proxy)
./target/release/greentunnelRS --bind 0.0.0.0 --port 8080 --dns-addr "127.0.0.1:55"
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