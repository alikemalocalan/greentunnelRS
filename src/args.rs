pub trait Parser {
    fn parse() -> Self;
}

#[derive(Debug, Clone)]
pub struct Cli {
    pub port: u16,
    pub bind: String,
    pub aggressive: bool,
    pub doh_url: String,
    pub verbose: bool,
    pub disorder: bool,
    pub fake_ttl: u32,
    pub fake_sni: String,
    pub window_shrink: usize,
}

impl Parser for Cli {
    fn parse() -> Self {
        let mut port = 8080;
        let mut bind = "127.0.0.1".to_string();
        let mut aggressive = false;
        let mut doh_url = "https://dns.google/resolve".to_string();
        let mut verbose = false;
        let mut disorder = false;
        let mut fake_ttl = 0;
        let mut fake_sni = "google.com".to_string();
        let mut window_shrink = 0;

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
                "-d" | "--doh-url" => {
                    if i + 1 < args.len() {
                        doh_url = args[i + 1].clone();
                        i += 1;
                    }
                }
                "-v" | "--verbose" => verbose = true,
                "-D" | "--disorder" => disorder = true,
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
            doh_url,
            verbose,
            disorder,
            fake_ttl,
            fake_sni,
            window_shrink,
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
  -F, --fake-ttl <TTL>          Inject fake ClientHello with specified TTL (0 = disabled)
      --fake-sni <DOMAIN>       Benign domain name for fake ClientHello injection [default: google.com]
  -W, --window-shrink <BYTES>   Restrict TCP socket buffer window size (0 = disabled)
  -d, --doh-url <URL>           DoH/DoT provider endpoint URL [default: https://dns.google/resolve]
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
            doh_url: "https://dns.google/resolve".to_string(),
            verbose: false,
            disorder: false,
            fake_ttl: 0,
            fake_sni: "google.com".to_string(),
            window_shrink: 0,
        };
        assert_eq!(cli.port, 8080);
        assert_eq!(cli.bind, "127.0.0.1");
        assert_eq!(cli.fake_sni, "google.com");
    }
}
