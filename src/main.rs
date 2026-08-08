mod dns;
mod proxy;
mod tls;
mod utils;

use clap::Parser;
use proxy::{run_server, ProxyServerConfig};
use std::net::SocketAddr;

/// GreenTunnel CLI — High performance lightweight DPI bypass anti-censorship proxy in Rust.
#[derive(Parser, Debug)]
#[command(author, version, about = "GreenTunnel Rust — Ultra-fast anti-censorship proxy for Linux, macOS, Windows, and OpenWrt routers.", long_about = None)]
struct Cli {
    /// Port to listen on (e.g. 8080)
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// Bind IP address (e.g. 127.0.0.1 or 0.0.0.0 for LAN/OpenWrt)
    #[arg(short, long, default_value = "127.0.0.1")]
    bind: String,

    /// Enable Aggressive Mode (TLS ClientHello Padding - RFC 7685)
    #[arg(short, long, default_value_t = false)]
    aggressive: bool,

    /// DoH (DNS-over-HTTPS) provider endpoint URL
    #[arg(short, long, default_value = "https://dns.google/resolve")]
    doh_url: String,

    /// Verbose log output
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Enable Out-of-Order TCP Disorder transmission (sends Record 2 before Record 1)
    #[arg(short = 'D', long, default_value_t = false)]
    disorder: bool,

    /// Inject a fake ClientHello packet with low TTL to mislead ISP DPI (0 = disabled)
    #[arg(short = 'F', long, default_value_t = 0)]
    fake_ttl: u32,

    /// Benign domain to use in fake ClientHello injection
    #[arg(long, default_value = "google.com")]
    fake_sni: String,

    /// Restrict TCP socket buffer window size to force micro-segmentation (0 = disabled)
    #[arg(short = 'W', long, default_value_t = 0)]
    window_shrink: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install ring as default Rustls crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let cli = Cli::parse();

    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(format!("greentunnel={}", log_level))
            }),
        )
        .init();

    let bind_addr: SocketAddr = format!("{}:{}", cli.bind, cli.port).parse()?;

    println!(
        r#"
  ________                       ___________                          .__ 
 /  _____/______  ____   ____   _\__    ___/__ __  ____   ____   ____ |  |
/   \  __\_  __ \/ __ \_/ __ \ / \ |    | |  |  \/    \ /    \_/ __ \|  |
\    \_\  \  | \/\  ___/\  ___/ /  |    | |  |  /   |  \   |  \  ___/|  |__
 \______  /__|    \___  >\___  >   |____| |____/|___|  /___|  /\___  >____/
        \/            \/     \/                      \/     \/     \/     
"#
    );

    let config = ProxyServerConfig {
        bind_addr,
        aggressive_mode: cli.aggressive,
        doh_url: cli.doh_url,
        disorder_mode: cli.disorder,
        fake_ttl: cli.fake_ttl,
        fake_sni: cli.fake_sni,
        window_shrink: cli.window_shrink,
    };

    run_server(config).await?;

    Ok(())
}
