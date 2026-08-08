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

/// Splits a buffer into small randomized TCP segments (40-160 bytes) and writes them out.
pub async fn split_and_write(data: &[u8], stream: &mut TcpStream) -> Result<(), std::io::Error> {
    if data.is_empty() {
        return Ok(());
    }

    let mut offset = 0;
    while offset < data.len() {
        let chunk_size = rand::random_range(40..=160).min(data.len() - offset);
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
    header_line.to_uppercase().starts_with("CONNECT ")
}

/// Parses the target domain and port from an HTTP CONNECT line (e.g. "CONNECT youtube.com:443 HTTP/1.1").
pub fn parse_connect_target(request_str: &str) -> Option<(String, u16)> {
    let first_line = request_str.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 || parts[0].to_uppercase() != "CONNECT" {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_proxy_headers() {
        let req = "GET / HTTP/1.1\r\nHost: example.com\r\nVia: 1.1 proxy\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n";
        let cleaned = strip_proxy_headers(req);
        assert!(!cleaned.contains("Via:"));
        assert!(!cleaned.contains("X-Forwarded-For:"));
        assert!(cleaned.contains("Host: example.com"));
    }
}

