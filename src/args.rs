//! Command-line argument parsing for GreenTunnel Rust CLI.
//!
//! Provides a zero-dependency lightweight parser supporting both `--option value`
//! and `--option=value` syntax.

pub trait Parser {
    /// Parses command-line arguments from `std::env::args()`.
    fn parse() -> Self;
}

/// Command-line configuration parameters for the proxy server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cli {
    /// Local TCP port for the proxy server to listen on.
    pub port: u16,
    /// Local IP address to bind to.
    pub bind: String,
    /// Upstream UDP DNS resolver IP and port.
    pub dns_addr: String,
    /// Enables verbose debug level logging output.
    pub verbose: bool,
    /// Socket TTL value for fake ClientHello packet injection (0 = disabled).
    pub fake_ttl: u32,
    /// Benign SNI domain name for fake ClientHello injection.
    pub fake_sni: String,
    /// Socket TCP receive/send buffer window shrink size in bytes (0 = disabled).
    pub window_shrink: usize,
    /// Enables HTTP CONNECT extra space insertion desynchronization.
    pub http_space: bool,
    /// Enables HTTP header key case mixing desynchronization.
    pub mix_header_case: bool,
    /// Strips `Alt-Svc` headers to enforce TCP TLS 1.3 over censored QUIC UDP.
    pub strip_alt_svc: bool,
    /// Enables client TCP source port rotation on outbound connection retries.
    pub port_rotate: bool,
    /// Appends root FQDN trailing dot (`example.com.`) to break domain regex matchers.
    pub trailing_dot: bool,
    /// Filters out malicious DNS Type 65 (HTTPS) / Type 64 (SVCB) records.
    pub filter_type65: bool,
    /// Target fallback IP:port for serving benign 404 HTML banners to ISP active probes.
    pub fallback_target: String,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            port: 8080,
            bind: "127.0.0.1".to_string(),
            dns_addr: "127.0.0.1:53".to_string(),
            verbose: false,
            fake_ttl: 0,
            fake_sni: String::new(),
            window_shrink: 0,
            http_space: true,
            mix_header_case: true,
            strip_alt_svc: true,
            port_rotate: true,
            trailing_dot: true,
            filter_type65: true,
            fallback_target: "127.0.0.1:80".to_string(),
        }
    }
}

impl Cli {
    /// Parses CLI arguments from an arbitrary iterator of strings (used for testing and runtime execution).
    pub fn parse_from<I, T>(args: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let args_vec: Vec<String> = args.into_iter().map(Into::into).collect();
        let mut cli = Self::default();

        let mut i = 1;
        while i < args_vec.len() {
            let arg = &args_vec[i];

            if let Some((key, val)) = arg.split_once('=') {
                match key {
                    "-p" | "--port" => {
                        if let Ok(val_parsed) = val.parse() {
                            cli.port = val_parsed;
                        }
                    }
                    "-b" | "--bind" => cli.bind = val.to_string(),
                    "-d" | "--dns-addr" | "--doh-url" => cli.dns_addr = val.to_string(),
                    "--fallback-target" => cli.fallback_target = val.to_string(),
                    "-F" | "--fake-ttl" => {
                        if let Ok(val_parsed) = val.parse() {
                            cli.fake_ttl = val_parsed;
                        }
                    }
                    "--fake-sni" => cli.fake_sni = val.to_string(),
                    "-W" | "--window-shrink" => {
                        if let Ok(val_parsed) = val.parse() {
                            cli.window_shrink = val_parsed;
                        }
                    }
                    _ => {}
                }
            } else {
                match arg.as_str() {
                    "-p" | "--port" => {
                        if i + 1 < args_vec.len() {
                            if let Ok(val_parsed) = args_vec[i + 1].parse() {
                                cli.port = val_parsed;
                            }
                            i += 1;
                        }
                    }
                    "-b" | "--bind" => {
                        if i + 1 < args_vec.len() {
                            cli.bind = args_vec[i + 1].clone();
                            i += 1;
                        }
                    }
                    "-d" | "--dns-addr" | "--doh-url" => {
                        if i + 1 < args_vec.len() {
                            cli.dns_addr = args_vec[i + 1].clone();
                            i += 1;
                        }
                    }
                    "-v" | "--verbose" => cli.verbose = true,
                    "-e" | "--http-space" => cli.http_space = true,
                    "-m" | "--mix-header-case" => cli.mix_header_case = true,
                    "-s" | "--strip-alt-svc" => cli.strip_alt_svc = true,
                    "-R" | "--port-rotate" => cli.port_rotate = true,
                    "-t" | "--trailing-dot" => cli.trailing_dot = true,
                    "-T" | "--filter-type65" => cli.filter_type65 = true,
                    "--fallback-target" => {
                        if i + 1 < args_vec.len() {
                            cli.fallback_target = args_vec[i + 1].clone();
                            i += 1;
                        }
                    }
                    "-F" | "--fake-ttl" => {
                        if i + 1 < args_vec.len() {
                            if let Ok(val_parsed) = args_vec[i + 1].parse() {
                                cli.fake_ttl = val_parsed;
                            }
                            i += 1;
                        }
                    }
                    "--fake-sni" => {
                        if i + 1 < args_vec.len() {
                            cli.fake_sni = args_vec[i + 1].clone();
                            i += 1;
                        }
                    }
                    "-W" | "--window-shrink" => {
                        if i + 1 < args_vec.len() {
                            if let Ok(val_parsed) = args_vec[i + 1].parse() {
                                cli.window_shrink = val_parsed;
                            }
                            i += 1;
                        }
                    }
                    "-h" | "--help" => {
                        print_help();
                        std::process::exit(0);
                    }
                    "-V" | "--version" => {
                        println!("greentunnelRS 0.1.0");
                        std::process::exit(0);
                    }
                    _ => {}
                }
            }
            i += 1;
        }

        cli
    }
}

impl Parser for Cli {
    fn parse() -> Self {
        Self::parse_from(std::env::args())
    }
}

/// Prints help and usage information to standard output.
pub fn print_help() {
    println!(
        r#"GreenTunnel Rust — Ultra-fast anti-censorship DPI bypass proxy for Linux, macOS, Windows, and OpenWrt routers.

Usage: greentunnelRS [OPTIONS]

Options:
  -p, --port <PORT>             Port to listen on [default: 8080]
  -b, --bind <IP>               Bind IP address (e.g. 127.0.0.1 or 0.0.0.0) [default: 127.0.0.1]
  -e, --http-space              Enable HTTP CONNECT extra space insertion desynchronization
  -m, --mix-header-case         Enable HTTP header key case mixing desynchronization
  -s, --strip-alt-svc           Strip Alt-Svc headers to enforce TCP TLS 1.3 over censored QUIC UDP [default: true]
  -R, --port-rotate             Enable TCP source port rotation on connection retries [default: true]
  -t, --trailing-dot            Append root FQDN trailing dot (example.com.) to break DPI regex filters
  -T, --filter-type65           Filter out poisoned DNS Type 65 (HTTPS/SVCB) records [default: true]
      --fallback-target <IP:PORT> Active probing fallback response target [default: 127.0.0.1:80]
  -F, --fake-ttl <TTL>          Inject fake ClientHello with specified TTL [default: 0 (disabled)]
      --fake-sni <DOMAIN>       Benign domain name for fake ClientHello injection [default: disabled]
  -W, --window-shrink <BYTES>   Restrict TCP socket buffer window size [default: 0 (disabled)]
  -d, --dns-addr <IP:PORT>      DNS resolver server IP:port [default: 127.0.0.1:53]
  -v, --verbose                 Enable verbose debug log output
  -h, --help                    Print help information
  -V, --version                 Print version information

Examples:
  # Basic run on localhost port 8080:
  greentunnelRS --port 8080

  # Run with Fake TTL Packet Injection enabled (fake google.com SNI with TTL 5):
  greentunnelRS --port 8080 --fake-ttl 5 --fake-sni google.com

  # Advanced DPI bypass with Fake TTL and DNS:
  greentunnelRS -F 5 --fake-sni google.com -d 127.0.0.1:53"#
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_cli_values() {
        let cli = Cli::default();
        assert_eq!(cli.port, 8080);
        assert_eq!(cli.bind, "127.0.0.1");
        assert_eq!(cli.dns_addr, "127.0.0.1:53");
        assert_eq!(cli.fake_sni, "");
        assert_eq!(cli.fake_ttl, 0);
        assert_eq!(cli.window_shrink, 0);
        assert!(cli.http_space);
        assert!(cli.mix_header_case);
        assert!(cli.strip_alt_svc);
        assert!(cli.port_rotate);
        assert!(cli.trailing_dot);
        assert!(cli.filter_type65);
        assert_eq!(cli.fallback_target, "127.0.0.1:80");
    }

    #[test]
    fn test_parse_from_custom_flags() {
        let args = vec![
            "greentunnelRS",
            "--port",
            "9090",
            "--bind",
            "0.0.0.0",
            "-d",
            "1.1.1.1:53",
            "-v",
            "-F",
            "5",
            "--fake-sni",
            "google.com",
            "-W",
            "4096",
            "--fallback-target",
            "192.168.1.1:80",
        ];
        let cli = Cli::parse_from(args);
        assert_eq!(cli.port, 9090);
        assert_eq!(cli.bind, "0.0.0.0");
        assert_eq!(cli.dns_addr, "1.1.1.1:53");
        assert!(cli.verbose);
        assert_eq!(cli.fake_ttl, 5);
        assert_eq!(cli.fake_sni, "google.com");
        assert_eq!(cli.window_shrink, 4096);
        assert_eq!(cli.fallback_target, "192.168.1.1:80");
    }

    #[test]
    fn test_parse_from_equals_syntax() {
        let args = vec![
            "greentunnelRS",
            "--port=9999",
            "--bind=10.0.0.1",
            "--dns-addr=8.8.8.8:53",
            "--fake-ttl=10",
            "--fake-sni=cloudflare.com",
            "--window-shrink=8192",
            "--fallback-target=10.0.0.1:8080",
        ];
        let cli = Cli::parse_from(args);
        assert_eq!(cli.port, 9999);
        assert_eq!(cli.bind, "10.0.0.1");
        assert_eq!(cli.dns_addr, "8.8.8.8:53");
        assert_eq!(cli.fake_ttl, 10);
        assert_eq!(cli.fake_sni, "cloudflare.com");
        assert_eq!(cli.window_shrink, 8192);
        assert_eq!(cli.fallback_target, "10.0.0.1:8080");
    }
}
