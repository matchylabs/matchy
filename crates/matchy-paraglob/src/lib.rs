//! Unified Pattern Matcher - Combines Aho-Corasick and Glob Matching
//!
//! Paraglob provides multi-pattern matching combining literal strings and glob patterns
//! in a single optimized data structure.

// Internal modules
mod paraglob_offset;
pub(crate) mod literal_hash;

// Temporary modules until Phase 8 (will be extracted to matchy-format)
pub(crate) mod endian;
pub(crate) mod error;
pub(crate) mod offset_format;
pub(crate) mod simd_utils;

// Re-export main types
pub use paraglob_offset::{Paraglob, ParaglobBuilder};

// Re-export MatchMode from shared crate
pub use matchy_match_mode::MatchMode;
