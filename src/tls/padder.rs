use super::parser::{find_extensions_length_offset, is_client_hello, read_u16, TLS_RECORD_HEADER_SIZE};

pub const PADDING_EXTENSION_TYPE: u16 = 0x0015;
pub const DEFAULT_TARGET_SIZE: usize = 512;

/// Pads a TLS ClientHello byte slice to `target_size` bytes using TLS Padding Extension (0x0015).
///
/// Returns original vector unmodified if:
/// - Data is not a valid ClientHello
/// - Padding extension (0x0015) already exists
/// - ClientHello size is already >= `target_size`
pub fn pad(data: &[u8], target_size: usize) -> Vec<u8> {
    if !is_client_hello(data) {
        return data.to_vec();
    }

    if data.len() >= target_size {
        return data.to_vec();
    }

    if has_padding_extension(data) {
        return data.to_vec();
    }

    let padding_needed = target_size - data.len();
    if padding_needed < 4 {
        return data.to_vec();
    }

    let ext_len_offset = match find_extensions_length_offset(data) {
        Some(offset) => offset,
        None => return data.to_vec(),
    };

    let orig_ext_len = match read_u16(data, ext_len_offset) {
        Some(len) => len as usize,
        None => return data.to_vec(),
    };

    let ext_end = ext_len_offset + 2 + orig_ext_len;
    if ext_end > data.len() {
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
    let mut padded = Vec::with_capacity(data.len() + padding_needed);
    padded.extend_from_slice(&data[..ext_end]);
    padded.extend_from_slice(&padding_extension);
    if data.len() > ext_end {
        padded.extend_from_slice(&data[ext_end..]);
    }

    // 1. Update TLS Record Length (bytes 3-4)
    let new_record_len = (padded.len() - TLS_RECORD_HEADER_SIZE) as u16;
    padded[3] = ((new_record_len >> 8) & 0xFF) as u8;
    padded[4] = (new_record_len & 0xFF) as u8;

    // 2. Update Handshake Header Length (bytes 6-8, 24-bit uint)
    let orig_handshake_len = ((data[6] as u32) << 16) | ((data[7] as u32) << 8) | (data[8] as u32);
    let new_handshake_len = orig_handshake_len + padding_needed as u32;
    padded[6] = ((new_handshake_len >> 16) & 0xFF) as u8;
    padded[7] = ((new_handshake_len >> 8) & 0xFF) as u8;
    padded[8] = (new_handshake_len & 0xFF) as u8;

    // 3. Update Extensions Length (bytes at ext_len_offset)
    let new_ext_len = (orig_ext_len + padding_needed) as u16;
    padded[ext_len_offset] = ((new_ext_len >> 8) & 0xFF) as u8;
    padded[ext_len_offset + 1] = (new_ext_len & 0xFF) as u8;

    tracing::info!(
        "Aggressive Mode (Rust): Padded ClientHello from {} to {} bytes (+{} padding bytes)",
        data.len(),
        padded.len(),
        padding_needed
    );

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
    use crate::tls::parser::tests::build_synthetic_client_hello;

    #[test]
    fn test_pad_small_client_hello() {
        let original = build_synthetic_client_hello(Some("example.com"), false);
        assert!(original.len() < DEFAULT_TARGET_SIZE);

        let padded = pad(&original, DEFAULT_TARGET_SIZE);
        assert_eq!(padded.len(), DEFAULT_TARGET_SIZE);

        // Check if padding extension 0x0015 was added
        assert!(has_padding_extension(&padded));
    }

    #[test]
    fn test_skip_padding_if_already_padded() {
        let original = build_synthetic_client_hello(Some("example.com"), true);
        let padded = pad(&original, DEFAULT_TARGET_SIZE);
        assert_eq!(original, padded);
    }
}
