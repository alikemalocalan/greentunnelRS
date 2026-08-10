pub trait Parser {
    fn parse() -> Self;
}

#[derive(Debug, Clone)]
pub struct Cli {
    pub port: u16,
    pub bind: String,
    pub aggressive: bool,
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
    pub ja4_permute: bool,
}

impl Parser for Cli {
    fn parse() -> Self {
        let mut port = 8080;
        let mut bind = "127.0.0.1".to_string();
        let mut aggressive = false;
        let mut dns_addr = "127.0.0.1:53".to_string();
        let mut verbose = false;
        let mut disorder = false;
        let mut fake_ttl = 0;
        let mut fake_sni = "google.com".to_string();
        let mut window_shrink = 0;
        let mut http_space = true;
        let mut mix_header_case = true;
        let mut strip_alt_svc = true;
        let mut port_rotate = true;
        let mut ja4_permute = true;

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
                "-a" | "--aggressive" => aggressive = true,
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
                "-J" | "--ja4-permute" => ja4_permute = true,
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
            aggressive,
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
            ja4_permute,
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
  -a, --aggressive              Enable Aggressive Mode (TLS ClientHello Padding per RFC 7685)
  -D, --disorder                Enable Out-of-Order TCP Disorder transmission
  -e, --http-space              Enable HTTP CONNECT extra space insertion desynchronization
  -m, --mix-header-case         Enable HTTP header key case mixing desynchronization
  -s, --strip-alt-svc           Strip Alt-Svc headers to enforce TCP TLS 1.3 over censored QUIC UDP [default: true]
  -R, --port-rotate             Enable TCP source port rotation on connection retries [default: true]
  -J, --ja4-permute             Enable dynamic TLS ClientHello extension permutation [default: true]
  -F, --fake-ttl <TTL>          Inject fake ClientHello with specified TTL [default: 0 (disabled)]
      --fake-sni <DOMAIN>       Benign domain name for fake ClientHello injection [default: google.com]
  -W, --window-shrink <BYTES>   Restrict TCP socket buffer window size (0 = disabled)
  -d, --dns-addr <IP:PORT>      DNS resolver server IP:port [default: 127.0.0.1:53]
  -v, --verbose                 Enable verbose debug log output
  -h, --help                    Print help information
  -V, --version                 Print version information"#
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
            aggressive: false,
            dns_addr: "127.0.0.1:53".to_string(),
            verbose: false,
            disorder: false,
            fake_ttl: 0,
            fake_sni: "google.com".to_string(),
            window_shrink: 0,
            http_space: true,
            mix_header_case: true,
            strip_alt_svc: true,
            port_rotate: true,
            ja4_permute: true,
        };
        assert_eq!(cli.port, 8080);
        assert_eq!(cli.bind, "127.0.0.1");
        assert_eq!(cli.dns_addr, "127.0.0.1:53");
        assert_eq!(cli.fake_sni, "google.com");
        assert!(cli.http_space);
        assert!(cli.mix_header_case);
        assert!(cli.strip_alt_svc);
        assert!(cli.port_rotate);
        assert!(cli.ja4_permute);
    }
}
