//! Error types for matchy format operations

use std::fmt;

/// Errors that can occur during database format operations
#[derive(Debug, Clone)]
pub enum FormatError {
    /// Invalid IP address or CIDR notation
    InvalidIpAddress(String),
    /// Invalid pattern syntax
    InvalidPattern(String),
    /// IP tree building error
    IpTreeError(String),
    /// Pattern matching error
    PatternError(String),
    /// Literal hash error
    LiteralHashError(String),
    /// I/O error
    IoError(String),
    /// Generic error
    Other(String),
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::InvalidIpAddress(msg) => write!(f, "Invalid IP address: {}", msg),
            FormatError::InvalidPattern(msg) => write!(f, "Invalid pattern: {}", msg),
            FormatError::IpTreeError(msg) => write!(f, "IP tree error: {}", msg),
            FormatError::PatternError(msg) => write!(f, "Pattern error: {}", msg),
            FormatError::LiteralHashError(msg) => write!(f, "Literal hash error: {}", msg),
            FormatError::IoError(msg) => write!(f, "I/O error: {}", msg),
            FormatError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for FormatError {}

// Conversions from component errors
impl From<matchy_paraglob::error::ParaglobError> for FormatError {
    fn from(err: matchy_paraglob::error::ParaglobError) -> Self {
        FormatError::PatternError(err.to_string())
    }
}

impl From<matchy_literal_hash::LiteralHashError> for FormatError {
    fn from(err: matchy_literal_hash::LiteralHashError) -> Self {
        FormatError::LiteralHashError(err.to_string())
    }
}

impl From<matchy_ip_trie::IpTreeError> for FormatError {
    fn from(err: matchy_ip_trie::IpTreeError) -> Self {
        FormatError::IpTreeError(err.to_string())
    }
}

impl From<std::io::Error> for FormatError {
    fn from(err: std::io::Error) -> Self {
        FormatError::IoError(err.to_string())
    }
}

impl From<String> for FormatError {
    fn from(s: String) -> Self {
        FormatError::Other(s)
    }
}

impl From<&str> for FormatError {
    fn from(s: &str) -> Self {
        FormatError::Other(s.to_string())
    }
}

// Conversion: FormatError -> ParaglobError
// This allows code that uses ParaglobError to also accept FormatError.
// When matchy-format operations fail, they can be converted into ParaglobError
// so the caller can handle both types uniformly.
impl From<FormatError> for matchy_paraglob::error::ParaglobError {
    fn from(err: FormatError) -> Self {
        use matchy_paraglob::error::ParaglobError;
        match err {
            FormatError::InvalidIpAddress(msg) | FormatError::InvalidPattern(msg) => {
                ParaglobError::InvalidPattern(msg)
            }
            FormatError::IoError(msg) => ParaglobError::Io(msg),
            FormatError::IpTreeError(msg)
            | FormatError::PatternError(msg)
            | FormatError::LiteralHashError(msg)
            | FormatError::Other(msg) => ParaglobError::Other(msg),
        }
    }
}
