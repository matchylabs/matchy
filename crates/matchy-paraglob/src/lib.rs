//! Unified Pattern Matcher - Combines Aho-Corasick and Glob Matching
//!
//! Paraglob provides multi-pattern matching combining literal strings and glob patterns
//! in a single optimized data structure.

// Internal modules
pub(crate) mod glob;
pub(crate) mod literal_hash;
mod paraglob_offset;

// Temporary modules until Phase 8 (will be extracted to matchy-format)
pub mod error; // Public so matchy-format can use ParaglobError
pub mod offset_format; // Public for validation and external format access
pub(crate) mod simd_utils;

// Re-export main types
pub use paraglob_offset::{Paraglob, ParaglobBuilder};

// Re-export MatchMode from shared crate
pub use matchy_match_mode::MatchMode;

// Re-export GlobError for external error handling
pub use glob::GlobError;

/// Validate a glob pattern without building a matcher.
///
/// This is useful for validating user input before adding it to a database.
///
/// # Examples
///
/// ```
/// use matchy_paraglob::validate_glob_pattern;
///
/// // Valid patterns
/// assert!(validate_glob_pattern("*.txt").is_ok());
/// assert!(validate_glob_pattern("file[0-9].txt").is_ok());
///
/// // Invalid patterns
/// assert!(validate_glob_pattern("[unclosed").is_err());
/// assert!(validate_glob_pattern("file\\").is_err());  // Trailing backslash
/// ```
pub fn validate_glob_pattern(pattern: &str) -> Result<(), GlobError> {
    // Use CaseSensitive for validation - mode doesn't matter for syntax checking
    glob::GlobPattern::new(pattern, MatchMode::CaseSensitive)?;
    Ok(())
}

// Validation module for paraglob structures
pub mod validation;

// Re-export validation types for convenience
pub use validation::{
    build_pattern_info, validate_ac_literal_mapping, validate_meta_word_mappings,
    validate_patterns, ParaglobStats, ParaglobValidationResult,
};
