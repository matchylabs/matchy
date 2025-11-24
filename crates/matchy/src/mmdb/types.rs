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

/// Record size in bits
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordSize {
    /// 24-bit records (3 bytes per record, 6 bytes per node)
    Bits24 = 24,
    /// 28-bit records (3.5 bytes per record, 7 bytes per node)
    Bits28 = 28,
    /// 32-bit records (4 bytes per record, 8 bytes per node)
    Bits32 = 32,
}

impl RecordSize {
    /// Get the size of a single record in bytes (may be fractional)
    pub fn record_bytes(self) -> f64 {
        match self {
            RecordSize::Bits24 => 3.0,
            RecordSize::Bits28 => 3.5,
            RecordSize::Bits32 => 4.0,
        }
    }

    /// Get the size of a node (2 records) in bytes
    pub fn node_bytes(self) -> usize {
        match self {
            RecordSize::Bits24 => 6,
            RecordSize::Bits28 => 7,
            RecordSize::Bits32 => 8,
        }
    }

    /// Create from bit size
    pub fn from_bits(bits: u16) -> Result<Self, MmdbError> {
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
}
