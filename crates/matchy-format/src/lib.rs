//! Matchy Database File Format
//!
//! This crate provides the binary format for matchy databases, combining:
//! - IP trie (from matchy-ip-trie)
//! - Pattern matching (from matchy-paraglob)
//! - Data section (from matchy-data-format)
//!
//! The format orchestrates all three components into a unified .mxy file.

// Public modules
pub mod error;
pub mod mmdb;
pub mod offset_format;

// Internal modules (types re-exported below)
mod mmdb_builder;
mod validation;

// Re-exports
pub use error::FormatError;
pub use matchy_literal_hash;
pub use mmdb_builder::{BuilderStats, DatabaseBuilder, EntryType};
pub use offset_format::*;
pub use validation::{validate_data_mapping_consistency, FormatStats, FormatValidationResult};
