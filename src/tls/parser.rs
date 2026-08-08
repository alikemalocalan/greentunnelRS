pub const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
pub const SNI_EXTENSION_TYPE: u16 = 0x0000;
pub const TLS_RECORD_HEADER_SIZE: usize = 5;

#[derive(Debug, Clone, Copy)]
pub struct SniInfo {
    pub hostname_offset: usize,
    pub hostname_length: usize,
}

/// Checks if a byte slice starts with a valid TLS ClientHello.
pub fn is_client_hello(data: &[u8]) -> bool {
    if data.len() < 6 {
        return false;
    }
    data[0] == TLS_CONTENT_TYPE_HANDSHAKE && data[5] == HANDSHAKE_TYPE_CLIENT_HELLO
}

/// Finds the offset and length of the SNI hostname within a TLS ClientHello binary record.
pub fn find_sni_info(data: &[u8]) -> Option<SniInfo> {
    if data.len() < 6 {
        return None;
    }
    if data[0] != TLS_CONTENT_TYPE_HANDSHAKE || data[5] != HANDSHAKE_TYPE_CLIENT_HELLO {
        return None;
    }

    let mut pos = TLS_RECORD_HEADER_SIZE; // Skip 5-byte record header

    // Handshake header: type(1) + length(3)
    pos += 4;

    // Client version(2) + random(32)
    pos += 34;

    // Session ID: len(1) + data(N)
    if pos >= data.len() {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites: len(2) + data(M)
    if pos + 2 > data.len() {
        return None;
    }
    let cipher_suites_len = read_u16(data, pos)? as usize;
    pos += 2 + cipher_suites_len;

    // Compression methods: len(1) + data(K)
    if pos >= data.len() {
        return None;
    }
    let compression_len = data[pos] as usize;
    pos += 1 + compression_len;

    // Extensions length: len(2)
    if pos + 2 > data.len() {
        return None;
    }
    let extensions_len = read_u16(data, pos)? as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;

    // Scan each extension for SNI (0x0000)
    while pos + 4 <= extensions_end && pos + 4 <= data.len() {
        let ext_type = read_u16(data, pos)?;
        let ext_len = read_u16(data, pos + 2)? as usize;
        pos += 4;

        if ext_type == SNI_EXTENSION_TYPE {
            if pos + 5 > data.len() {
                return None;
            }
            let hostname_len = read_u16(data, pos + 3)? as usize;
            let hostname_offset = pos + 5;

            if hostname_offset + hostname_len > data.len() {
                return None;
            }

            return Some(SniInfo {
                hostname_offset,
                hostname_length: hostname_len,
            });
        }

        pos += ext_len;
    }

    None
}

/// Locates the byte offset of the Extensions Length (2 bytes) field in ClientHello.
pub fn find_extensions_length_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 44 {
        return None;
    }

    let mut pos = TLS_RECORD_HEADER_SIZE;
    pos += 4; // Handshake header
    pos += 34; // Version + Random

    if pos >= data.len() {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;

    if pos + 2 > data.len() {
        return None;
    }
    let cipher_suites_len = read_u16(data, pos)? as usize;
    pos += 2 + cipher_suites_len;

    if pos >= data.len() {
        return None;
    }
    let compression_len = data[pos] as usize;
    pos += 1 + compression_len;

    if pos + 2 > data.len() {
        return None;
    }

    Some(pos)
}

pub fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() {
        None
    } else {
        Some(((data[offset] as u16) << 8) | (data[offset + 1] as u16))
    }
}

/// Builds a minimal synthetic ClientHello record for testing or fake packet injection.
pub fn build_synthetic_client_hello(hostname: Option<&str>, include_padding: bool) -> Vec<u8> {
    let mut extensions_data = Vec::new();

    if let Some(host) = hostname {
        let host_bytes = host.as_bytes();
        let sni_ext_data_len = (2 + 1 + 2 + host_bytes.len()) as u16;

        extensions_data.push(0x00);
        extensions_data.push(0x00);
        extensions_data.push(((sni_ext_data_len >> 8) & 0xFF) as u8);
        extensions_data.push((sni_ext_data_len & 0xFF) as u8);

        let sni_list_len = (1 + 2 + host_bytes.len()) as u16;
        extensions_data.push(((sni_list_len >> 8) & 0xFF) as u8);
        extensions_data.push((sni_list_len & 0xFF) as u8);
        extensions_data.push(0x00);
        extensions_data.push(((host_bytes.len() >> 8) & 0xFF) as u8);
        extensions_data.push((host_bytes.len() & 0xFF) as u8);
        extensions_data.extend_from_slice(host_bytes);
    }

    if include_padding {
        extensions_data.push(0x00);
        extensions_data.push(0x15);
        extensions_data.push(0x00);
        extensions_data.push(0x0A);
        extensions_data.extend_from_slice(&[0u8; 10]);
    }

    let mut hs_body = Vec::new();
    hs_body.push(0x03);
    hs_body.push(0x03);
    hs_body.extend_from_slice(&[0u8; 32]);
    hs_body.push(0x00); // session id len
    hs_body.push(0x00); // cipher suites len high
    hs_body.push(0x02); // cipher suites len low
    hs_body.push(0x00);
    hs_body.push(0x2F);
    hs_body.push(0x01); // compression len
    hs_body.push(0x00);

    let ext_len = extensions_data.len() as u16;
    hs_body.push(((ext_len >> 8) & 0xFF) as u8);
    hs_body.push((ext_len & 0xFF) as u8);
    hs_body.extend_from_slice(&extensions_data);

    let hs_len = (4 + hs_body.len()) as u16;
    let mut record = Vec::new();
    record.push(0x16);
    record.push(0x03);
    record.push(0x01);
    record.push(((hs_len >> 8) & 0xFF) as u8);
    record.push((hs_len & 0xFF) as u8);

    record.push(0x01); // ClientHello
    record.push(0x00);
    let body_len = hs_body.len() as u16;
    record.push(((body_len >> 8) & 0xFF) as u8);
    record.push((body_len & 0xFF) as u8);
    record.extend_from_slice(&hs_body);

    record
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_is_client_hello() {
        let valid = vec![0x16, 0x03, 0x03, 0x00, 0x10, 0x01];
        assert!(is_client_hello(&valid));

        let invalid = b"GET / HTTP/1.1\r\n";
        assert!(!is_client_hello(invalid));
    }

    #[test]
    fn test_find_sni_info() {
        let client_hello = build_synthetic_client_hello(Some("example.com"), false);
        let sni_info = find_sni_info(&client_hello).expect("SNI should be found");
        assert_eq!(sni_info.hostname_length, "example.com".len());
        let extracted = std::str::from_utf8(&client_hello[sni_info.hostname_offset..sni_info.hostname_offset + sni_info.hostname_length]).unwrap();
        assert_eq!(extracted, "example.com");
    }
}
