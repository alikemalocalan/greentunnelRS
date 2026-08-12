//! Zero-dependency UDP DNS resolver with zero-allocation RFC 1035 parser and Type 65/64 record filtering.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

/// Default DNS resolver fallback endpoint.
pub const DEFAULT_DNS_ADDR: &str = "127.0.0.1:53";
/// RFC 1035 fixed header length in bytes.
pub const DNS_HEADER_SIZE: usize = 12;
/// Minimum Resource Record fixed header size (TYPE + CLASS + TTL + RDLENGTH).
pub const DNS_RR_HEADER_MIN_SIZE: usize = 10;
/// DNS Resource Record Type A (IPv4 host address).
pub const DNS_TYPE_A: u16 = 1;
/// DNS Resource Record Type 64 (SVCB - Service Binding).
pub const DNS_TYPE_SVCB: u16 = 64;
/// DNS Resource Record Type 65 (HTTPS - Service Binding for HTTPS).
pub const DNS_TYPE_HTTPS: u16 = 65;
/// DNS Class IN (Internet).
pub const DNS_CLASS_IN: u16 = 1;
/// DNS standard query flag with recursion desired (`0x0100`).
pub const DNS_FLAGS_STANDARD_QUERY: u16 = 0x0100;

/// Fast, lightweight UDP DNS resolver querying local loopback or configured resolver.
pub struct DnsResolver {
    dns_addr: String,
}

impl DnsResolver {
    /// Creates a new `DnsResolver` instance with the specified target IP:port string.
    pub fn new(dns_addr: &str) -> Self {
        let addr = if dns_addr.is_empty() {
            DEFAULT_DNS_ADDR.to_string()
        } else if !dns_addr.contains(':') {
            format!("{}:53", dns_addr)
        } else {
            dns_addr.to_string()
        };

        Self { dns_addr: addr }
    }

    /// Resolves a domain hostname to an `IpAddr` using direct UDP DNS query or system fallback.
    pub async fn resolve(&self, domain: &str) -> Option<IpAddr> {
        let clean_domain = domain.trim_end_matches('.');

        // Fast path: if domain is already a valid IP address
        if let Ok(ip) = clean_domain.parse::<IpAddr>() {
            return Some(ip);
        }

        let (query_buf, query_len) = build_dns_query(clean_domain);
        if query_len == 0 {
            return None;
        }

        // Try direct UDP DNS query to local loopback / resolver (zero-heap allocation)
        if let Some(ip) = self.query_udp(&query_buf[..query_len]).await {
            return Some(ip);
        }

        // Fallback: system resolution if UDP socket query fails or times out
        if let Ok(mut addrs) = tokio::net::lookup_host(format!("{}:443", clean_domain)).await {
            if let Some(addr) = addrs.next() {
                return Some(addr.ip());
            }
        }

        None
    }

    async fn query_udp(&self, query_msg: &[u8]) -> Option<IpAddr> {
        let bind_addr: SocketAddr = "0.0.0.0:0".parse().ok()?;
        let socket = UdpSocket::bind(bind_addr).await.ok()?;
        let target_addr: SocketAddr = self.dns_addr.parse().ok()?;

        for _attempt in 0..2 {
            if socket.send_to(query_msg, target_addr).await.is_err() {
                continue;
            }

            let mut buf = [0u8; 512];
            let timeout = std::time::Duration::from_millis(2500);

            if let Ok(Ok((len, _))) =
                tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await
            {
                if let Some(ip) = parse_dns_response(&buf[..len]) {
                    return Some(ip);
                }
            }
        }

        None
    }
}

/// Builds an RFC 1035 compliant binary DNS query packet for Type A IPv4 host lookup into a stack-allocated buffer.
pub fn build_dns_query(domain: &str) -> ([u8; 128], usize) {
    let mut query = [0u8; 128];
    if domain.len() > 100 {
        return (query, 0);
    }

    let tx_id: u16 = 1;
    query[0..2].copy_from_slice(&tx_id.to_be_bytes());
    query[2..4].copy_from_slice(&DNS_FLAGS_STANDARD_QUERY.to_be_bytes());

    // Question count: 1, Answer count: 0, Authority count: 0, Additional count: 0
    query[4..6].copy_from_slice(&1u16.to_be_bytes());
    query[6..8].copy_from_slice(&0u16.to_be_bytes());
    query[8..10].copy_from_slice(&0u16.to_be_bytes());
    query[10..12].copy_from_slice(&0u16.to_be_bytes());

    let mut pos = DNS_HEADER_SIZE;

    // QNAME: dot-separated domain labels
    for part in domain.split('.') {
        let bytes = part.as_bytes();
        if !bytes.is_empty() && pos + 1 + bytes.len() < 120 {
            query[pos] = bytes.len() as u8;
            pos += 1;
            query[pos..pos + bytes.len()].copy_from_slice(bytes);
            pos += bytes.len();
        }
    }
    query[pos] = 0x00;
    pos += 1;

    // QTYPE: 1 (A), QCLASS: 1 (IN)
    query[pos..pos + 2].copy_from_slice(&DNS_TYPE_A.to_be_bytes());
    pos += 2;
    query[pos..pos + 2].copy_from_slice(&DNS_CLASS_IN.to_be_bytes());
    pos += 2;

    (query, pos)
}

/// Parses an RFC 1035 binary DNS response packet and extracts the first IPv4 A-record address.
/// Also filters out DNS Type 65 (HTTPS) / Type 64 (SVCB) records to evade ISP DNS poisoning.
pub fn parse_dns_response(data: &[u8]) -> Option<IpAddr> {
    if data.len() < DNS_HEADER_SIZE {
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

    let mut pos = DNS_HEADER_SIZE;

    // Skip Question section
    for _ in 0..qdcount {
        let next_pos = skip_dns_name(data, pos)?;
        pos = next_pos + 4; // Skip QTYPE (2) + QCLASS (2)
    }

    // Parse Answer section records
    for _ in 0..ancount {
        let Some(next_pos) = skip_dns_name(data, pos) else {
            break;
        };
        pos = next_pos;
        if pos + DNS_RR_HEADER_MIN_SIZE > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += DNS_RR_HEADER_MIN_SIZE;

        if pos + rdlen > data.len() {
            break;
        }

        // DNS Type 65 (HTTPS) and Type 64 (SVCB) filtering to prevent ISP DNS poisoning
        if rtype == DNS_TYPE_HTTPS || rtype == DNS_TYPE_SVCB {
            pos += rdlen;
            continue;
        }

        if rtype == DNS_TYPE_A && rdlen == 4 {
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

/// Helper function to skip a domain label string in a binary DNS packet (supporting compression pointers).
fn skip_dns_name(data: &[u8], mut pos: usize) -> Option<usize> {
    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        // Check for DNS pointer compression (`0xC0`)
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
        let (query, len) = build_dns_query("example.com");
        assert!(len > DNS_HEADER_SIZE);
        assert_eq!(query[2], 0x01); // Flags high byte
        assert_eq!(query[3], 0x00); // Flags low byte
    }

    #[test]
    fn test_dns_resolver_new_defaults() {
        let resolver = DnsResolver::new("");
        assert_eq!(resolver.dns_addr, DEFAULT_DNS_ADDR);

        let resolver_ip_only = DnsResolver::new("8.8.8.8");
        assert_eq!(resolver_ip_only.dns_addr, "8.8.8.8:53");

        let resolver_full = DnsResolver::new("1.1.1.1:53");
        assert_eq!(resolver_full.dns_addr, "1.1.1.1:53");
    }

    #[test]
    fn test_parse_dns_response_valid_a_record() {
        // Construct synthetic DNS response for example.com -> 93.184.216.34
        let mut packet = vec![
            0x00, 0x01, // Tx ID
            0x81, 0x80, // Standard response, No error
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, 0x00, 0x00, // NSCOUNT, ARCOUNT
        ];
        // Question section: example.com, Type A, Class IN
        packet.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00,
            0x01,
        ]);
        // Answer section: compression ptr 0xC00C, Type A (1), Class IN (1), TTL (300), RDLEN (4), IP (93.184.216.34)
        packet.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 93, 184, 216,
            34,
        ]);

        let resolved_ip = parse_dns_response(&packet);
        assert_eq!(
            resolved_ip,
            Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))
        );
    }

    #[test]
    fn test_parse_dns_response_filters_type65() {
        // Response containing Type 65 record first, then Type A record
        let mut packet = vec![
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, // 2 answers
            0x00, 0x00, 0x00, 0x00,
        ];
        // Question
        packet.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00,
            0x01,
        ]);
        // Answer 1: Type 65 (HTTPS), RDLEN = 5
        packet.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 65, 0x00, 0x01, 0x00, 0x00, 0x00, 60, 0x00, 0x05, 0x01, 0x02, 0x03,
            0x04, 0x05,
        ]);
        // Answer 2: Type A (1), IP (1.1.1.1)
        packet.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 60, 0x00, 0x04, 1, 1, 1, 1,
        ]);

        let resolved_ip = parse_dns_response(&packet);
        assert_eq!(resolved_ip, Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }
}
