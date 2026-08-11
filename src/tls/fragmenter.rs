use super::parser::TLS_RECORD_HEADER_SIZE;

/// Represents a TLS record slice with a zero-allocation header and zero-copy payload slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsRecordSlice<'a> {
    pub header: [u8; TLS_RECORD_HEADER_SIZE],
    pub payload: &'a [u8],
}

impl<'a> TlsRecordSlice<'a> {
    #[inline]
    pub fn len(&self) -> usize {
        TLS_RECORD_HEADER_SIZE + self.payload.len()
    }
}

/// Builds a 5-byte TLS record header on the stack without heap allocation.
#[inline]
pub fn build_tls_header(
    content_type: u8,
    version_major: u8,
    version_minor: u8,
    payload_len: usize,
) -> [u8; TLS_RECORD_HEADER_SIZE] {
    let len = payload_len as u16;
    [
        content_type,
        version_major,
        version_minor,
        ((len >> 8) & 0xFF) as u8,
        (len & 0xFF) as u8,
    ]
}

/// Zero-allocation TLS record fragmenter.
/// Splits a TLS Record payload into two valid TLS record slices at `absolute_split_offset`.
pub fn fragment_at_offset<'a>(
    data: &'a [u8],
    absolute_split_offset: usize,
) -> (TlsRecordSlice<'a>, Option<TlsRecordSlice<'a>>) {
    if data.len() <= TLS_RECORD_HEADER_SIZE
        || absolute_split_offset <= TLS_RECORD_HEADER_SIZE
        || absolute_split_offset >= data.len()
    {
        let content_type = if !data.is_empty() { data[0] } else { 0x16 };
        let version_major = if data.len() > 1 { data[1] } else { 0x03 };
        let version_minor = if data.len() > 2 { data[2] } else { 0x01 };
        let payload = if data.len() >= TLS_RECORD_HEADER_SIZE {
            &data[TLS_RECORD_HEADER_SIZE..]
        } else {
            &[]
        };

        return (
            TlsRecordSlice {
                header: build_tls_header(content_type, version_major, version_minor, payload.len()),
                payload,
            },
            None,
        );
    }

    let content_type = data[0];
    let version_major = data[1];
    let version_minor = data[2];

    let payload1 = &data[TLS_RECORD_HEADER_SIZE..absolute_split_offset];
    let payload2 = &data[absolute_split_offset..];

    let record1 = TlsRecordSlice {
        header: build_tls_header(content_type, version_major, version_minor, payload1.len()),
        payload: payload1,
    };
    let record2 = TlsRecordSlice {
        header: build_tls_header(content_type, version_major, version_minor, payload2.len()),
        payload: payload2,
    };

    tracing::debug!(
        "TLS Record split (Rust zero-copy): {} bytes -> [{} + {}] bytes at offset {}",
        data.len(),
        record1.len(),
        record2.len(),
        absolute_split_offset
    );

    (record1, Some(record2))
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::parser::build_synthetic_client_hello;

    #[test]
    fn test_fragment_at_offset() {
        let client_hello = build_synthetic_client_hello(Some("example.com"), false);
        let (rec1, rec2) = fragment_at_offset(&client_hello, 40);
        let rec2 = rec2.expect("Should produce second record");

        assert_eq!(rec1.header[0], 0x16);
        assert_eq!(rec2.header[0], 0x16);
        // Verify outer TLS record layer version matches client's record version (bytes 1-2)
        assert_eq!(rec1.header[1], client_hello[1]);
        assert_eq!(rec1.header[2], client_hello[2]);
        assert_eq!(rec2.header[1], client_hello[1]);
        assert_eq!(rec2.header[2], client_hello[2]);

        // Verify combined payload length equals original payload
        let payload1_len = rec1.payload.len();
        let payload2_len = rec2.payload.len();
        assert_eq!(payload1_len + payload2_len, client_hello.len() - TLS_RECORD_HEADER_SIZE);
    }
}
