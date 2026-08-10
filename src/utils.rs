use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub const PROXY_HEADERS_TO_REMOVE: &[&str] = &[
    "client-ip",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "forwarded",
    "via",
    "proxy-authorization",
    "proxy-connection",
];

/// Splits a buffer into small randomized TCP segments (80-256 bytes) and writes them out.
pub async fn split_and_write(data: &[u8], stream: &mut TcpStream) -> Result<(), std::io::Error> {
    if data.is_empty() {
        return Ok(());
    }

    let mut offset = 0;
    while offset < data.len() {
        let chunk_size = rand::random_range(80..=256).min(data.len() - offset);
        let chunk = &data[offset..offset + chunk_size];
        stream.write_all(chunk).await?;
        offset += chunk_size;
    }
    stream.flush().await?;
    Ok(())
}

/// Pauses execution for a random duration between `min_ms` and `max_ms`.
pub async fn random_delay(min_ms: u64, max_ms: u64) {
    let delay_ms = rand::random_range(min_ms..=max_ms);
    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
}

/// Checks if a string case-insensitively starts with an HTTP CONNECT method.
pub fn is_http_connect(header_line: &str) -> bool {
    let trimmed = header_line.trim_start();
    let first_word = trimmed.split_whitespace().next().unwrap_or("");
    first_word.eq_ignore_ascii_case("CONNECT")
}

/// Detects domains (like Meta/Instagram/Facebook/WhatsApp) whose proprietary TLS stack (Fizz TLS) rejects TLS padding extensions.
pub fn is_padding_incompatible_domain(host: &str) -> bool {
    let lower = host.to_lowercase();
    lower.ends_with("instagram.com")
        || lower.ends_with("facebook.com")
        || lower.ends_with("fbcdn.net")
        || lower.ends_with("cdninstagram.com")
        || lower.ends_with("messenger.com")
        || lower.ends_with("whatsapp.net")
        || lower.ends_with("whatsapp.com")
}

/// Parses the target domain and port from an HTTP CONNECT line (e.g. "CONNECT youtube.com:443 HTTP/1.1").
pub fn parse_connect_target(request_str: &str) -> Option<(String, u16)> {
    let first_line = request_str.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 || !parts[0].eq_ignore_ascii_case("CONNECT") {
        return None;
    }

    let target = parts[1];
    let mut host_port = target.split(':');
    let host = host_port.next()?.to_string();
    let port = host_port.next().unwrap_or("443").parse::<u16>().ok()?;
    Some((host, port))
}

/// Strips proxy headers from an HTTP request header string.
pub fn strip_proxy_headers(request_str: &str) -> String {
    let mut lines = Vec::new();
    for (i, line) in request_str.lines().enumerate() {
        if i == 0 {
            lines.push(line.to_string());
            continue;
        }
        if line.is_empty() {
            lines.push(line.to_string());
            break;
        }
        if let Some((key, _)) = line.split_once(':') {
            let key_trim = key.trim();
            if PROXY_HEADERS_TO_REMOVE
                .iter()
                .any(|&h| h.eq_ignore_ascii_case(key_trim))
            {
                continue;
            }
        }
        lines.push(line.to_string());
    }
    lines.join("\r\n")
}

/// Inserts extra space padding into an HTTP request line to confuse DPI regex splitters.
pub fn apply_connect_space_insertion(request_line: &str) -> String {
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() >= 3 {
        format!("{}   {}   {}", parts[0], parts[1], parts[2])
    } else if parts.len() == 2 {
        format!("{}   {}", parts[0], parts[1])
    } else {
        request_line.to_string()
    }
}

/// Alternates letter casing of a string (e.g. "Host" -> "hOsT").
pub fn mix_case(s: &str) -> String {
    s.chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_lowercase()
            } else {
                c.to_ascii_uppercase()
            }
        })
        .collect()
}

/// Applies header key case mixing desynchronization to HTTP header strings.
pub fn apply_header_case_mixing(request_str: &str) -> String {
    let mut lines = Vec::new();
    for (i, line) in request_str.lines().enumerate() {
        if i == 0 {
            if let Some((method, rest)) = line.split_once(' ') {
                lines.push(format!("{} {}", mix_case(method), rest));
            } else {
                lines.push(line.to_string());
            }
            continue;
        }
        if line.is_empty() {
            lines.push(line.to_string());
            break;
        }
        if let Some((key, val)) = line.split_once(':') {
            let mixed_key = mix_case(key.trim());
            lines.push(format!("{}:{}", mixed_key, val));
        } else {
            lines.push(line.to_string());
        }
    }
    lines.join("\r\n")
}

/// Preprocesses HTTP request string by stripping proxy headers, applying HTTP CONNECT space insertion, and header case mixing.
pub fn preprocess_http_request(request_str: &str, http_space: bool, mix_header_case: bool) -> String {
    let mut processed = strip_proxy_headers(request_str);
    if http_space {
        let first_line = processed.lines().next().unwrap_or("").to_string();
        let modified_line = apply_connect_space_insertion(&first_line);
        let rest = if processed.contains("\r\n") {
            processed.split_once("\r\n").map(|(_, r)| r).unwrap_or("")
        } else if processed.contains('\n') {
            processed.split_once('\n').map(|(_, r)| r).unwrap_or("")
        } else {
            ""
        };
        processed = if rest.is_empty() {
            modified_line
        } else {
            format!("{}\r\n{}", modified_line, rest)
        };
    }
    if mix_header_case {
        processed = apply_header_case_mixing(&processed);
    }
    processed
}

/// Strips Alt-Svc / alt-svc headers from an HTTP response header block to prevent browsers from switching to censored QUIC UDP traffic.
#[allow(dead_code)]
pub fn strip_alt_svc_headers(response_str: &str) -> String {
    let mut lines = Vec::new();
    for line in response_str.lines() {
        if let Some((key, _)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case("alt-svc") {
                continue;
            }
        }
        lines.push(line.to_string());
    }
    lines.join("\r\n")
}

/// Appends root FQDN trailing dot to domain name if missing (e.g. "example.com" -> "example.com.") to break exact domain string matching in DPI middleboxes.
pub fn ensure_trailing_dot(host: &str) -> String {
    if host.is_empty() || host.ends_with('.') || host.parse::<std::net::IpAddr>().is_ok() {
        host.to_string()
    } else {
        format!("{}.", host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_proxy_headers() {
        let req = "CONNECT youtube.com:443 HTTP/1.1\r\nVia: 1.1 proxy\r\nProxy-Connection: keep-alive\r\nHost: youtube.com\r\n\r\n";
        let cleaned = strip_proxy_headers(req);
        assert!(!cleaned.contains("Via:"));
        assert!(!cleaned.contains("Proxy-Connection:"));
        assert!(cleaned.contains("Host: youtube.com"));
    }

    #[test]
    fn test_is_padding_incompatible_domain() {
        assert!(is_padding_incompatible_domain("instagram.com"));
        assert!(is_padding_incompatible_domain("www.instagram.com"));
        assert!(is_padding_incompatible_domain("facebook.com"));
        assert!(!is_padding_incompatible_domain("youtube.com"));
        assert!(!is_padding_incompatible_domain("wikipedia.org"));
    }

    #[test]
    fn test_space_insertion_and_case_mixing() {
        let req = "CONNECT instagram.com:443 HTTP/1.1\r\nHost: instagram.com:443\r\nUser-Agent: curl/7.68.0\r\n\r\n";
        assert!(is_http_connect(req));
        assert_eq!(parse_connect_target(req), Some(("instagram.com".to_string(), 443)));

        let preprocessed = preprocess_http_request(req, true, true);
        assert!(preprocessed.contains("instagram.com:443"));
        assert!(is_http_connect(&preprocessed));
        assert_eq!(parse_connect_target(&preprocessed), Some(("instagram.com".to_string(), 443)));
        assert!(preprocessed.contains("   ")); // multi space check
        assert!(preprocessed.contains("hOsT:")); // mixed case check
    }

    #[test]
    fn test_strip_alt_svc_headers() {
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nalt-svc: h3-29=\":443\"\r\nServer: gws\r\n\r\n";
        let cleaned = strip_alt_svc_headers(resp);
        assert!(!cleaned.contains("Alt-Svc:"));
        assert!(!cleaned.contains("alt-svc:"));
        assert!(cleaned.contains("Server: gws"));
    }

    #[test]
    fn test_ensure_trailing_dot() {
        assert_eq!(ensure_trailing_dot("youtube.com"), "youtube.com.");
        assert_eq!(ensure_trailing_dot("youtube.com."), "youtube.com.");
        assert_eq!(ensure_trailing_dot("127.0.0.1"), "127.0.0.1");
        assert_eq!(ensure_trailing_dot(""), "");
    }
}
