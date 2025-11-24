//! MMDB-specific Type Definitions
//!
//! MMDB-specific types. Data values use the existing `DataValue` type
//! from `data_section` module which is already MMDB-compatible.

use std::fmt;

/// MMDB metadata marker: "\xAB\xCD\xEFMaxMind.com"
pub const METADATA_MARKER: &[u8] = b"\xAB\xCD\xEFMaxMind.com";

/// MMDB-specific error types
#[derive(Debug, Clone)]
pub enum MmdbError {
    /// Invalid file format
    InvalidFormat(String),
    /// Metadata not found
    MetadataNotFound,
    /// Invalid metadata structure
    InvalidMetadata(String),
    /// Data decoding error (wraps DataDecoder errors)
    DecodeError(String),
    /// IO error
    IoError(String),
    /// Invalid IP address
    InvalidIpAddress(String),
    /// Network/IP lookup error
    LookupError(String),
}

impl fmt::Display for MmdbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MmdbError::InvalidFormat(msg) => write!(f, "Invalid MMDB format: {}", msg),
            MmdbError::MetadataNotFound => write!(f, "MMDB metadata marker not found"),
            MmdbError::InvalidMetadata(msg) => write!(f, "Invalid metadata: {}", msg),
            MmdbError::DecodeError(msg) => write!(f, "Data decode error: {}", msg),
            MmdbError::IoError(msg) => write!(f, "IO error: {}", msg),
            MmdbError::InvalidIpAddress(msg) => write!(f, "Invalid IP address: {}", msg),
            MmdbError::LookupError(msg) => write!(f, "Lookup error: {}", msg),
        }
    }
}

impl std::error::Error for MmdbError {}

// Convert data_section errors to MmdbError
impl From<String> for MmdbError {
    fn from(msg: String) -> Self {
        MmdbError::DecodeError(msg)
    }
}

/// IP version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    /// IPv4 only
    V4,
    /// IPv6 (may include IPv4-mapped addresses)
    V6,
}

// Re-export RecordSize from ip-trie (it's an IP trie concern, not MMDB-specific)
pub use matchy_ip_trie::RecordSize;

// Helper function for MMDB metadata parsing
pub fn record_size_from_bits(bits: u16) -> Result<RecordSize, MmdbError> {
    match bits {
        24 => Ok(RecordSize::Bits24),
        28 => Ok(RecordSize::Bits28),
        32 => Ok(RecordSize::Bits32),
        _ => Err(MmdbError::InvalidFormat(format!(
            "Invalid record size: {} bits",
            bits
        ))),
    }
}
