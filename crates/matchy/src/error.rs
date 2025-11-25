//! Error types for the matchy library
//!
//! Matchy uses a unified error type that wraps errors from all sub-components.
//! This provides clean error handling while maintaining proper abstraction boundaries.

use thiserror::Error;

/// Main error type for matchy operations
///
/// This error type wraps all possible errors that can occur during matchy operations,
/// including pattern matching, database format operations, and I/O.
#[derive(Error, Debug)]
pub enum MatchyError {
    /// Error from paraglob pattern matching operations
    #[error(transparent)]
    Paraglob(#[from] matchy_paraglob::error::ParaglobError),

    /// Error from database format operations
    #[error(transparent)]
    Format(#[from] matchy_format::FormatError),

    /// I/O error
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Database error
    #[error("{0}")]
    Database(String),

    /// Validation error
    #[error("{0}")]
    Validation(String),
}

/// Result type alias for matchy operations
pub type Result<T> = std::result::Result<T, MatchyError>;

// Convenient conversions for common error types
impl From<String> for MatchyError {
    fn from(s: String) -> Self {
        MatchyError::Database(s)
    }
}

impl From<&str> for MatchyError {
    fn from(s: &str) -> Self {
        MatchyError::Database(s.to_string())
    }
}

// Re-export component error types for users who need them
pub use matchy_format::FormatError;
pub use matchy_paraglob::error::ParaglobError;
