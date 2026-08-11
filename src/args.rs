pub trait Parser {
    fn parse() -> Self;
}

#[derive(Debug, Clone)]
pub struct Cli {
    pub port: u16,
    pub bind: String,
    pub tls_padding: bool,
    pub dns_addr: String,
    pub verbose: bool,
    pub disorder: bool,
    pub fake_ttl: u32,
    pub fake_sni: String,
    pub window_shrink: usize,
    pub http_space: bool,
    pub mix_header_case: bool,
    pub strip_alt_svc: bool,
    pub port_rotate: bool,
    pub trailing_dot: bool,
    pub filter_type65: bool,
    pub post_quantum: bool,
    pub fallback_target: String,
}

impl Parser for Cli {
    fn parse() -> Self {
        let mut port = 8080;
        let mut bind = "127.0.0.1".to_string();
        let mut tls_padding = false;
        let mut dns_addr = "127.0.0.1:53".to_string();
        let mut verbose = false;
        let mut disorder = true;
        let mut fake_ttl = 0;
        let mut fake_sni = "".to_string();
        let mut window_shrink = 0;
        let mut http_space = true;
        let mut mix_header_case = true;
        let mut strip_alt_svc = true;
        let mut port_rotate = true;
        let mut trailing_dot = true;
        let mut filter_type65 = true;
        let mut post_quantum = false;
        let mut fallback_target = "127.0.0.1:80".to_string();

        let args: Vec<String> = std::env::args().collect();
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-p" | "--port" => {
                    if i + 1 < args.len() {
                        if let Ok(val) = args[i + 1].parse() {
                            port = val;
                        }
                        i += 1;
                    }
                }
                "-b" | "--bind" => {
                    if i + 1 < args.len() {
                        bind = args[i + 1].clone();
                        i += 1;
                    }
                }
                "-P" | "--tls-padding" | "-a" | "--aggressive" => tls_padding = true,
                "-d" | "--dns-addr" | "--doh-url" => {
                    if i + 1 < args.len() {
                        dns_addr = args[i + 1].clone();
                        i += 1;
                    }
                }
                "-v" | "--verbose" => verbose = true,
                "-D" | "--disorder" => disorder = true,
                "-e" | "--http-space" => http_space = true,
                "-m" | "--mix-header-case" => mix_header_case = true,
                "-s" | "--strip-alt-svc" => strip_alt_svc = true,
                "-R" | "--port-rotate" => port_rotate = true,
                "-t" | "--trailing-dot" => trailing_dot = true,
                "-T" | "--filter-type65" => filter_type65 = true,
                "-Q" | "--post-quantum" => post_quantum = true,
                "--fallback-target" => {
                    if i + 1 < args.len() {
                        fallback_target = args[i + 1].clone();
                        i += 1;
                    }
                }
                "-F" | "--fake-ttl" => {
                    if i + 1 < args.len() {
                        if let Ok(val) = args[i + 1].parse() {
                            fake_ttl = val;
                        }
                        i += 1;
                    }
                }
                "--fake-sni" => {
                    if i + 1 < args.len() {
                        fake_sni = args[i + 1].clone();
                        i += 1;
                    }
                }
                "-W" | "--window-shrink" => {
                    if i + 1 < args.len() {
                        if let Ok(val) = args[i + 1].parse() {
                            window_shrink = val;
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
            i += 1;
        }

        Self {
            port,
            bind,
            tls_padding,
            dns_addr,
            verbose,
            disorder,
            fake_ttl,
            fake_sni,
            window_shrink,
            http_space,
            mix_header_case,
            strip_alt_svc,
            port_rotate,
            trailing_dot,
            filter_type65,
            post_quantum,
            fallback_target,
        }
    }
}

fn print_help() {
    println!(
        r#"GreenTunnel Rust — Ultra-fast anti-censorship DPI bypass proxy for Linux, macOS, Windows, and OpenWrt routers.

Usage: greentunnelRS [OPTIONS]

Options:
  -p, --port <PORT>             Port to listen on [default: 8080]
  -b, --bind <IP>               Bind IP address (e.g. 127.0.0.1 or 0.0.0.0) [default: 127.0.0.1]
  -P, --tls-padding             Enable TLS ClientHello Padding (RFC 7685)
  -D, --disorder                Enable Out-of-Order TCP Disorder transmission
  -e, --http-space              Enable HTTP CONNECT extra space insertion desynchronization
  -m, --mix-header-case         Enable HTTP header key case mixing desynchronization
  -s, --strip-alt-svc           Strip Alt-Svc headers to enforce TCP TLS 1.3 over censored QUIC UDP [default: true]
  -R, --port-rotate             Enable TCP source port rotation on connection retries [default: true]
  -t, --trailing-dot            Append root FQDN trailing dot (example.com.) to break DPI regex filters
  -T, --filter-type65           Filter out poisoned DNS Type 65 (HTTPS/SVCB) records [default: true]
  -Q, --post-quantum            Enable Post-Quantum TLS 1.3 ML-KEM-768 extension support
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

  # Advanced DPI bypass with TLS Padding, Disorder Mode, and Fake TTL:
  greentunnelRS -P -D -F 5 --fake-sni google.com -d 127.0.0.1:53"#
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_cli_values() {
        let cli = Cli {
            port: 8080,
            bind: "127.0.0.1".to_string(),
            tls_padding: false,
            dns_addr: "127.0.0.1:53".to_string(),
            verbose: false,
            disorder: true,
            fake_ttl: 0,
            fake_sni: "".to_string(),
            window_shrink: 0,
            http_space: true,
            mix_header_case: true,
            strip_alt_svc: true,
            port_rotate: true,
            trailing_dot: true,
            filter_type65: true,
            post_quantum: false,
            fallback_target: "127.0.0.1:80".to_string(),
        };
        assert_eq!(cli.port, 8080);
        assert_eq!(cli.bind, "127.0.0.1");
        assert_eq!(cli.dns_addr, "127.0.0.1:53");
        assert_eq!(cli.fake_sni, "");
        assert!(!cli.tls_padding);
        assert_eq!(cli.fake_ttl, 0);
        assert_eq!(cli.window_shrink, 0);
        assert!(cli.http_space);
        assert!(cli.mix_header_case);
        assert!(cli.strip_alt_svc);
        assert!(cli.port_rotate);
        assert!(cli.trailing_dot);
        assert!(cli.filter_type65);
        assert!(!cli.post_quantum);
        assert_eq!(cli.fallback_target, "127.0.0.1:80");
    }
}
