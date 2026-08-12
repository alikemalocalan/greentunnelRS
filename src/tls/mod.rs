//! TLS binary record parsing and zero-copy record fragmentation module.

pub mod fragmenter;
pub mod parser;

pub use fragmenter::{fragment_at_offset, TlsRecordSlice};
pub use parser::{
    build_synthetic_client_hello, find_sni_info, is_client_hello, read_u16, TLS_RECORD_HEADER_SIZE,
};
