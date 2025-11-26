/// Error types for the matchy library
use std::fmt;

/// Result type alias for paraglob operations
pub type Result<T> = std::result::Result<T, ParaglobError>;

/// Main error type for paraglob operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParaglobError {
    /// Pattern-related errors
    InvalidPattern(String),

    /// I/O errors
    Io(String),

    /// Memory mapping errors
    Mmap(String),

    /// Format/parsing errors
    Format(String),

    /// Validation errors
    Validation(String),

    /// Serialization/deserialization errors
    SerializationError(String),

    /// Resource limit exceeded (e.g., too many states, too much memory)
    ResourceLimitExceeded(String),

    /// General errors
    Other(String),
}

impl fmt::Display for ParaglobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParaglobError::InvalidPattern(msg) => write!(f, "Invalid pattern: {}", msg),
            ParaglobError::Io(msg) => write!(f, "I/O error: {}", msg),
            ParaglobError::Mmap(msg) => write!(f, "Memory mapping error: {}", msg),
            ParaglobError::Format(msg) => write!(f, "Format error: {}", msg),
            ParaglobError::Validation(msg) => write!(f, "Validation error: {}", msg),
            ParaglobError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            ParaglobError::ResourceLimitExceeded(msg) => {
                write!(f, "Resource limit exceeded: {}", msg)
            }
            ParaglobError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ParaglobError {}

impl From<std::io::Error> for ParaglobError {
    fn from(err: std::io::Error) -> Self {
        ParaglobError::Io(err.to_string())
    }
}

impl From<String> for ParaglobError {
    fn from(msg: String) -> Self {
        ParaglobError::Other(msg)
    }
}

impl From<&str> for ParaglobError {
    fn from(msg: &str) -> Self {
        ParaglobError::Other(msg.to_string())
    }
}

impl From<crate::glob::GlobError> for ParaglobError {
    fn from(err: crate::glob::GlobError) -> Self {
        match err {
            crate::glob::GlobError::InvalidPattern(msg) => ParaglobError::InvalidPattern(msg),
        }
    }
}

impl From<matchy_ac::ACError> for ParaglobError {
    fn from(err: matchy_ac::ACError) -> Self {
        match err {
            matchy_ac::ACError::InvalidPattern(msg) => ParaglobError::InvalidPattern(msg),
            matchy_ac::ACError::ResourceLimitExceeded(msg) => {
                ParaglobError::ResourceLimitExceeded(msg)
            }
            matchy_ac::ACError::InvalidInput(msg) => ParaglobError::Other(msg),
        }
    }
}

impl From<matchy_ip_trie::IpTreeError> for ParaglobError {
    fn from(err: matchy_ip_trie::IpTreeError) -> Self {
        match err {
            matchy_ip_trie::IpTreeError::InvalidPattern(msg) => ParaglobError::InvalidPattern(msg),
            matchy_ip_trie::IpTreeError::ResourceLimitExceeded(msg) => {
                ParaglobError::ResourceLimitExceeded(msg)
            }
            matchy_ip_trie::IpTreeError::Other(msg) => ParaglobError::Other(msg),
        }
    }
}

// Note: matchy-format dependency would create a circular dependency
// This conversion is implemented in matchy crate which depends on both
