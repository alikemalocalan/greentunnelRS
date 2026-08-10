use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

pub struct DnsResolver {
    dns_addr: String,
    cache: Arc<RwLock<HashMap<String, IpAddr>>>,
}

impl DnsResolver {
    pub fn new(dns_addr: &str) -> Self {
        let addr = if dns_addr.is_empty() || dns_addr.contains("http") || dns_addr.contains("google") {
            "127.0.0.1:53".to_string()
        } else if !dns_addr.contains(':') {
            format!("{}:53", dns_addr)
        } else {
            dns_addr.to_string()
        };

        Self {
            dns_addr: addr,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Resolves a domain hostname to an IP address using fast zero-dependency local UDP DNS (127.0.0.1:53).
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

        tracing::debug!("UDP DNS resolving: {} via {}", domain, self.dns_addr);

        let query = build_dns_query(domain);

        // Try direct UDP DNS query to local loopback (127.0.0.1:53 / dnscrypt-proxy / dnsmasq)
        if let Some(resp_buf) = self.query_udp(&query).await {
            if let Some(ip) = parse_dns_response(&resp_buf) {
                tracing::debug!("UDP DNS resolved {} -> {}", domain, ip);
                let mut cache_write = self.cache.write().await;
                if cache_write.len() > 500 {
                    cache_write.clear();
                }
                cache_write.insert(domain.to_string(), ip);
                return Some(ip);
            }
        }

        // Fallback: tokio system resolution if UDP socket query fails or times out
        if let Ok(mut addrs) = tokio::net::lookup_host(format!("{}:443", domain)).await {
            if let Some(addr) = addrs.next() {
                let ip = addr.ip();
                tracing::debug!("System DNS resolved {} -> {}", domain, ip);
                let mut cache_write = self.cache.write().await;
                if cache_write.len() > 500 {
                    cache_write.clear();
                }
                cache_write.insert(domain.to_string(), ip);
                return Some(ip);
            }
        }

        tracing::warn!("All DNS resolution methods failed for {}", domain);
        None
    }

    async fn query_udp(&self, query_msg: &[u8]) -> Option<Vec<u8>> {
        let bind_addr: SocketAddr = "0.0.0.0:0".parse().ok()?;
        let socket = UdpSocket::bind(bind_addr).await.ok()?;
        let target_addr: SocketAddr = self.dns_addr.parse().ok()?;

        for attempt in 0..2 {
            if socket.send_to(query_msg, target_addr).await.is_err() {
                continue;
            }

            let mut buf = [0u8; 1024];
            let timeout = std::time::Duration::from_millis(2500);

            match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
                Ok(Ok((len, _))) => return Some(buf[..len].to_vec()),
                _ => {
                    tracing::debug!("UDP DNS query attempt {} timed out for {}", attempt + 1, self.dns_addr);
                }
            }
        }

        None
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
        let Some(next_pos) = skip_dns_name(data, pos) else { return None; };
        pos = next_pos + 4; // Skip QTYPE + QCLASS
    }

    // Parse Answer section records
    for _ in 0..ancount {
        let Some(next_pos) = skip_dns_name(data, pos) else { break; };
        pos = next_pos;
        if pos + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlen > data.len() {
            break;
        }

        // DNS Type 65 (0x0041 / HTTPS) and Type 64 (0x0040 / SVCB) filtering to prevent ISP DNS poisoning
        if rtype == 65 || rtype == 64 {
            tracing::info!("DNS Type {} (HTTPS/SVCB) record filtered to prevent ISP DNS poisoning desync", rtype);
            pos += rdlen;
            continue;
        }

        if rtype == 1 && rdlen == 4 {
            let ip = IpAddr::V4(Ipv4Addr::new(
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
            ));
            return Some(ip);
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
