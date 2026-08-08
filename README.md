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

## Build & Run

### 1. Build locally
```bash
cd rust
cargo build --release
```

### 2. Run CLI
```bash
# Basic run on port 8080
./target/release/greentunnel --port 8080

# Run with Aggressive Mode (TLS Padding enabled)
./target/release/greentunnel --port 8080 --aggressive

# Listen on all network interfaces (for OpenWrt / LAN router)
./target/release/greentunnel --bind 0.0.0.0 --port 8080 --aggressive
```

---

## Cross-Compiling for OpenWrt Routers

You can easily cross-compile the single binary for any OpenWrt router architecture:

### A. MIPS Big Endian (e.g. Atheros AR71XX / AR9331 routers)
```bash
rustup target add mips-unknown-linux-musl
cargo build --release --target mips-unknown-linux-musl
```

### B. MIPS Little Endian (e.g. MediaTek MT7620 / MT7621 routers)
```bash
rustup target add mipsel-unknown-linux-musl
cargo build --release --target mipsel-unknown-linux-musl
```

### C. ARM 64-bit (e.g. Raspberry Pi / Modern OpenWrt Routers)
```bash
rustup target add aarch64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

Copy the generated binary from `rust/target/<target>/release/greentunnel` to `/usr/bin/greentunnel` on your router.
