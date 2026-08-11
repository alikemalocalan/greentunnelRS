use super::parser::{find_extensions_length_offset, is_client_hello, read_u16, TLS_RECORD_HEADER_SIZE};

pub const PADDING_EXTENSION_TYPE: u16 = 0x0015;
pub const SUPPORTED_GROUPS_EXTENSION_TYPE: u16 = 0x000a;
pub const KEY_SHARE_EXTENSION_TYPE: u16 = 0x0033;
pub const DEFAULT_TARGET_SIZE: usize = 512;
pub const POST_QUANTUM_GROUP_X25519_MLKEM768: u16 = 0x11ec;

/// Robustly checks if a TLS ClientHello contains Post-Quantum hybrid key exchange / group (e.g. X25519_MLKEM768 0x11ec).
/// Safely parses TLV extensions (`supported_groups` 0x000a or `key_share` 0x0033) without panicking.
pub fn has_post_quantum_extension(data: &[u8]) -> bool {
    if !is_client_hello(data) {
        return false;
    }

    let ext_len_offset = match find_extensions_length_offset(data) {
        Some(offset) => offset,
        None => return false,
    };

    let ext_len = match read_u16(data, ext_len_offset) {
        Some(len) => len as usize,
        None => return false,
    };

    let mut pos = ext_len_offset + 2;
    let end = (pos + ext_len).min(data.len());

    while pos + 4 <= end {
        let ext_type = match read_u16(data, pos) {
            Some(t) => t,
            None => return false,
        };
        let ext_data_len = match read_u16(data, pos + 2) {
            Some(l) => l as usize,
            None => return false,
        };
        let ext_end = pos + 4 + ext_data_len;
        if ext_end > end {
            break;
        }

        let ext_payload = &data[pos + 4..ext_end];

        if (ext_type == SUPPORTED_GROUPS_EXTENSION_TYPE || ext_type == KEY_SHARE_EXTENSION_TYPE)
            && ext_payload
                .chunks_exact(2)
                .any(|c| u16::from_be_bytes([c[0], c[1]]) == POST_QUANTUM_GROUP_X25519_MLKEM768)
        {
            return true;
        }

        pos = ext_end;
    }

    false
}

/// Pads a TLS ClientHello byte slice to `target_size` bytes using TLS Padding Extension (0x0015).
///
/// Returns original vector unmodified if:
/// - Data is not a valid ClientHello
/// - Padding extension (0x0015) already exists
/// - ClientHello size is already >= `target_size`
pub fn pad_client_hello(data: &[u8], target_size: usize) -> Vec<u8> {
    if !is_client_hello(data) {
        return data.to_vec();
    }

    // Extract exact TLS record boundary if data contains trailing bytes
    let record_payload_len = match read_u16(data, 3) {
        Some(len) => len as usize,
        None => return data.to_vec(),
    };
    let record_len = TLS_RECORD_HEADER_SIZE + record_payload_len;

    let (record_data, trailing_data) = if data.len() > record_len {
        (&data[..record_len], &data[record_len..])
    } else {
        (data, &[][..])
    };

    if has_padding_extension(record_data) {
        return data.to_vec();
    }

    // Calculate proportional target size for ClientHello records.
    // Avoid inflating tiny ClientHellos (e.g. 163B) with massive padding (>50% of packet size),
    // because strict L7 load balancers drop ClientHellos where padding payload exceeds the body size.
    let max_padding_for_record = (record_data.len() / 2).clamp(32, 128);
    let target_for_record = record_data.len() + max_padding_for_record;

    let adaptive_target = if target_size == DEFAULT_TARGET_SIZE {
        target_size.min(target_for_record)
    } else {
        target_size
    };

    if record_data.len() >= adaptive_target {
        return data.to_vec();
    }

    let padding_needed = adaptive_target - record_data.len();
    if padding_needed < 4 {
        return data.to_vec();
    }

    let ext_len_offset = match find_extensions_length_offset(record_data) {
        Some(offset) => offset,
        None => return data.to_vec(),
    };

    let orig_ext_len = match read_u16(record_data, ext_len_offset) {
        Some(len) => len as usize,
        None => return data.to_vec(),
    };

    let ext_end = ext_len_offset + 2 + orig_ext_len;
    if ext_end > record_data.len() {
        return data.to_vec();
    }

    // Build padding extension: Type(2) + Length(2) + Payload(padding_needed - 4 zeros)
    let pad_ext_data_len = (padding_needed - 4) as u16;
    let mut padding_extension = vec![0u8; padding_needed];
    padding_extension[0] = ((PADDING_EXTENSION_TYPE >> 8) & 0xFF) as u8;
    padding_extension[1] = (PADDING_EXTENSION_TYPE & 0xFF) as u8;
    padding_extension[2] = ((pad_ext_data_len >> 8) & 0xFF) as u8;
    padding_extension[3] = (pad_ext_data_len & 0xFF) as u8;

    // Create padded vector and insert padding extension right at ext_end
    let mut padded = Vec::with_capacity(record_data.len() + padding_needed);
    padded.extend_from_slice(&record_data[..ext_end]);
    padded.extend_from_slice(&padding_extension);
    if record_data.len() > ext_end {
        padded.extend_from_slice(&record_data[ext_end..]);
    }

    // 1. Update TLS Record Length (bytes 3-4)
    let new_record_len = (padded.len() - TLS_RECORD_HEADER_SIZE) as u16;
    padded[3] = ((new_record_len >> 8) & 0xFF) as u8;
    padded[4] = (new_record_len & 0xFF) as u8;

    // 2. Update Handshake Header Length (bytes 6-8, 24-bit uint)
    let orig_handshake_len = ((record_data[6] as u32) << 16) | ((record_data[7] as u32) << 8) | (record_data[8] as u32);
    let new_handshake_len = orig_handshake_len + padding_needed as u32;
    padded[6] = ((new_handshake_len >> 16) & 0xFF) as u8;
    padded[7] = ((new_handshake_len >> 8) & 0xFF) as u8;
    padded[8] = (new_handshake_len & 0xFF) as u8;

    // 3. Update Extensions Length (bytes at ext_len_offset)
    let new_ext_len = (orig_ext_len + padding_needed) as u16;
    padded[ext_len_offset] = ((new_ext_len >> 8) & 0xFF) as u8;
    padded[ext_len_offset + 1] = (new_ext_len & 0xFF) as u8;

    tracing::info!(
        "TLS Padding (Rust): Padded ClientHello from {} to {} bytes (+{} padding bytes)",
        record_data.len(),
        padded.len(),
        padding_needed
    );

    if !trailing_data.is_empty() {
        padded.extend_from_slice(trailing_data);
    }

    padded
}

fn has_padding_extension(data: &[u8]) -> bool {
    let ext_len_offset = match find_extensions_length_offset(data) {
        Some(offset) => offset,
        None => return false,
    };
    let ext_len = match read_u16(data, ext_len_offset) {
        Some(len) => len as usize,
        None => return false,
    };
    let mut pos = ext_len_offset + 2;
    let end = pos + ext_len;

    while pos + 4 <= end && pos + 4 <= data.len() {
        let ext_type = match read_u16(data, pos) {
            Some(t) => t,
            None => return false,
        };
        let ext_data_len = match read_u16(data, pos + 2) {
            Some(l) => l as usize,
            None => return false,
        };
        if ext_type == PADDING_EXTENSION_TYPE {
            return true;
        }
        pos += 4 + ext_data_len;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::parser::build_synthetic_client_hello;

    #[test]
    fn test_pad_small_client_hello() {
        let original = build_synthetic_client_hello(Some("example.com"), false);
        assert!(original.len() < DEFAULT_TARGET_SIZE);

        let padded = pad_client_hello(&original, DEFAULT_TARGET_SIZE);
        assert!(padded.len() > original.len());
        assert!(has_padding_extension(&padded));
    }

    #[test]
    fn test_skip_padding_if_already_padded() {
        let original = build_synthetic_client_hello(Some("example.com"), true);
        let padded = pad_client_hello(&original, DEFAULT_TARGET_SIZE);
        assert_eq!(original, padded);
    }

    #[test]
    fn test_adaptive_padding() {
        let original = build_synthetic_client_hello(Some("example.com"), false);
        let expected_pad = (original.len() / 2).clamp(32, 128);
        let padded = pad_client_hello(&original, DEFAULT_TARGET_SIZE);
        assert_eq!(padded.len(), original.len() + expected_pad);
    }

    #[test]
    fn test_pad_with_trailing_data() {
        let mut original = build_synthetic_client_hello(Some("example.com"), false);
        let trailing = b"EXTRA_BYTES_IN_BUFFER";
        original.extend_from_slice(trailing);

        let padded = pad_client_hello(&original, DEFAULT_TARGET_SIZE);
        assert!(padded.ends_with(trailing));
    }

    #[test]
    fn test_has_post_quantum_extension() {
        let original = build_synthetic_client_hello(Some("example.com"), false);
        assert!(!has_post_quantum_extension(&original));
    }
}
