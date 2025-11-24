//! Error types for extraction operations

use std::fmt;

/// Error type for extractor operations
#[derive(Debug, Clone)]
pub enum ExtractorError {
    /// Invalid configuration
    InvalidConfig(String),
}

impl fmt::Display for ExtractorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtractorError::InvalidConfig(msg) => write!(f, "Invalid configuration: {}", msg),
        }
    }
}

impl std::error::Error for ExtractorError {}
