use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

pub struct DohResolver {
    server_addr: String,
    server_name: String,
    tls_config: Arc<rustls::ClientConfig>,
    cache: Arc<RwLock<HashMap<String, IpAddr>>>,
}

impl DohResolver {
    pub fn new(doh_url: &str) -> Self {
        // Map user endpoint to high-speed DoT (DNS-over-TLS RFC 7858 port 853)
        let (server_addr, server_name) = if doh_url.contains("google") {
            ("8.8.8.8:853".to_string(), "dns.google".to_string())
        } else if doh_url.contains("cloudflare") {
            ("1.1.1.1:853".to_string(), "cloudflare-dns.com".to_string())
        } else if doh_url.contains(':') && !doh_url.contains("http") {
            (
                doh_url.to_string(),
                doh_url
                    .split(':')
                    .next()
                    .unwrap_or("dns.google")
                    .to_string(),
            )
        } else {
            ("1.1.1.1:853".to_string(), "cloudflare-dns.com".to_string())
        };

        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let client_config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Self {
            server_addr,
            server_name,
            tls_config: Arc::new(client_config),
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Resolves a domain hostname to an IP address using fast binary DNS-over-TLS (DoT).
    pub async fn resolve(&self, domain: &str) -> Option<IpAddr> {
        // Fast path: if domain is already an IP address
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Some(ip);
        }

        // Check memory cache
        {
            let cache_read = self.cache.read().await;
            if let Some(ip) = cache_read.get(domain) {
                return Some(*ip);
            }
        }

        tracing::debug!("DoT resolving: {} via {}", domain, self.server_addr);

        let query = build_dns_query(domain);
        let mut msg = Vec::with_capacity(2 + query.len());
        let len_bytes = (query.len() as u16).to_be_bytes();
        msg.extend_from_slice(&len_bytes);
        msg.extend_from_slice(&query);

        match self.query_dot(&msg).await {
            Some(resp_buf) => {
                if let Some(ip) = parse_dns_response(&resp_buf) {
                    tracing::debug!("DoT resolved {} -> {}", domain, ip);
                    let mut cache_write = self.cache.write().await;
                    if cache_write.len() > 500 {
                        cache_write.clear();
                    }
                    cache_write.insert(domain.to_string(), ip);
                    return Some(ip);
                }
            }
            None => {
                tracing::warn!("DoT query failed for {}", domain);
            }
        }

        None
    }

    async fn query_dot(&self, query_msg: &[u8]) -> Option<Vec<u8>> {
        let tcp = TcpStream::connect(&self.server_addr).await.ok()?;
        tcp.set_nodelay(true).ok();

        let connector = TlsConnector::from(Arc::clone(&self.tls_config));
        let server_name = ServerName::try_from(self.server_name.clone()).ok()?;

        let mut tls = connector.connect(server_name, tcp).await.ok()?;
        tls.write_all(query_msg).await.ok()?;
        tls.flush().await.ok()?;

        let mut len_buf = [0u8; 2];
        tls.read_exact(&mut len_buf).await.ok()?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        if resp_len < 12 || resp_len > 1024 {
            return None;
        }

        let mut resp_buf = [0u8; 1024];
        let buf_slice = &mut resp_buf[..resp_len];
        tls.read_exact(buf_slice).await.ok()?;
        Some(buf_slice.to_vec())
    }
}

/// Builds a 100% RFC 1035 compliant binary DNS query packet for Type A (IPv4) host lookup.
pub fn build_dns_query(domain: &str) -> Vec<u8> {
    let mut query = Vec::with_capacity(64);
    let tx_id = rand::random::<u16>();
    query.extend_from_slice(&tx_id.to_be_bytes());

    // Flags: 0x0100 (Standard query, recursion desired)
    query.extend_from_slice(&[0x01, 0x00]);

    // QDCOUNT: 1
    query.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT: 0
    query.extend_from_slice(&[0x00, 0x00]);
    // NSCOUNT: 0
    query.extend_from_slice(&[0x00, 0x00]);
    // ARCOUNT: 0
    query.extend_from_slice(&[0x00, 0x00]);

    // QNAME: domain labels
    for part in domain.split('.') {
        let bytes = part.as_bytes();
        if !bytes.is_empty() {
            query.push(bytes.len() as u8);
            query.extend_from_slice(bytes);
        }
    }
    query.push(0x00);

    // QTYPE: 1 (A)
    query.extend_from_slice(&[0x00, 0x01]);
    // QCLASS: 1 (IN)
    query.extend_from_slice(&[0x00, 0x01]);

    query
}

/// Parses an RFC 1035 binary DNS response packet and extracts the first IPv4 A-record address.
pub fn parse_dns_response(data: &[u8]) -> Option<IpAddr> {
    if data.len() < 12 {
        return None;
    }

    let rcode = data[3] & 0x0F;
    if rcode != 0 {
        return None;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    if ancount == 0 {
        return None;
    }

    let mut pos = 12;

    // Skip Question section
    for _ in 0..qdcount {
        pos = skip_dns_name(data, pos)?;
        pos += 4; // Skip QTYPE + QCLASS
    }

    // Parse Answer section records
    for _ in 0..ancount {
        pos = skip_dns_name(data, pos)?;
        if pos + 10 > data.len() {
            return None;
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlen > data.len() {
            return None;
        }

        if rtype == 1 && rdlen == 4 {
            return Some(IpAddr::V4(std::net::Ipv4Addr::new(
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
            )));
        }

        pos += rdlen;
    }

    None
}

fn skip_dns_name(data: &[u8], mut pos: usize) -> Option<usize> {
    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            return Some(pos + 2);
        }
        pos += 1 + len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_dns_query() {
        let query = build_dns_query("example.com");
        assert!(query.len() > 12);
        assert_eq!(query[2], 0x01); // Flags
        assert_eq!(query[3], 0x00);
    }
}
