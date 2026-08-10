use super::parser::TLS_RECORD_HEADER_SIZE;

/// Splits a TLS Record payload into two valid TLS records at `absolute_split_offset`.
pub fn fragment_at_offset(data: &[u8], absolute_split_offset: usize) -> Vec<Vec<u8>> {
    if data.len() <= TLS_RECORD_HEADER_SIZE
        || absolute_split_offset <= TLS_RECORD_HEADER_SIZE
        || absolute_split_offset >= data.len()
    {
        return vec![data.to_vec()];
    }

    let content_type = data[0];
    // RFC 8446 Section 5.1: TLS 1.3 outer record layer headers MUST use legacy_record_version 0x0301 (TLS 1.0)
    let version_major = 0x03;
    let version_minor = 0x01;

    let payload1 = &data[TLS_RECORD_HEADER_SIZE..absolute_split_offset];
    let payload2 = &data[absolute_split_offset..];

    let record1 = build_tls_record(content_type, version_major, version_minor, payload1);
    let record2 = build_tls_record(content_type, version_major, version_minor, payload2);

    tracing::debug!(
        "TLS Record split (Rust): {} bytes -> [{} + {}] bytes at offset {}",
        data.len(),
        record1.len(),
        record2.len(),
        absolute_split_offset
    );

    vec![record1, record2]
}

pub fn build_tls_record(
    content_type: u8,
    version_major: u8,
    version_minor: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut record = Vec::with_capacity(TLS_RECORD_HEADER_SIZE + payload.len());
    record.push(content_type);
    record.push(version_major);
    record.push(version_minor);
    let len = payload.len() as u16;
    record.push(((len >> 8) & 0xFF) as u8);
    record.push((len & 0xFF) as u8);
    record.extend_from_slice(payload);
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::parser::build_synthetic_client_hello;

    #[test]
    fn test_fragment_at_offset() {
        let client_hello = build_synthetic_client_hello(Some("example.com"), false);
        let records = fragment_at_offset(&client_hello, 40);

        assert_eq!(records.len(), 2);
        assert_eq!(records[0][0], 0x16);
        assert_eq!(records[1][0], 0x16);

        // Verify combined payload length equals original payload
        let payload1_len = records[0].len() - TLS_RECORD_HEADER_SIZE;
        let payload2_len = records[1].len() - TLS_RECORD_HEADER_SIZE;
        assert_eq!(payload1_len + payload2_len, client_hello.len() - TLS_RECORD_HEADER_SIZE);
    }
}
