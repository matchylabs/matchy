//! Unified Pattern Matcher - Combines Aho-Corasick and Glob Matching
//!
//! Paraglob provides multi-pattern matching combining literal strings and glob patterns
//! in a single optimized data structure.

// Internal modules
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
