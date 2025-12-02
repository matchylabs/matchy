//! Matchy - Fast Database for IP Address and Pattern Matching
//!
//! Matchy is a high-performance database library for querying IP addresses, CIDR ranges,
//! and glob patterns with rich associated data. Perfect for threat intelligence, GeoIP,
//! domain categorization, and network security applications.
//!
//! # Quick Start - Unified Database
//!
//! ```rust
//! use matchy::{Database, DatabaseBuilder, MatchMode, DataValue};
//! use std::collections::HashMap;
//!
//! // Build a database with both IP and pattern entries
//! let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
//!
//! // Add IP address
//! let mut data = HashMap::new();
//! data.insert("threat_level".to_string(), DataValue::String("high".to_string()));
//! builder.add_entry("1.2.3.4", data)?;
//!
//! // Add pattern
//! let mut data = HashMap::new();
//! data.insert("category".to_string(), DataValue::String("malware".to_string()));
//! builder.add_entry("*.evil.com", data)?;
//!
//! // Build and save
//! let db_bytes = builder.build()?;
//! # let tmp_path = std::env::temp_dir().join("matchy_doctest_threats.db");
//! # std::fs::write(&tmp_path, db_bytes)?;
//!
//! // Query the database
//! # let db = Database::from(tmp_path.to_str().unwrap()).open()?;
//! # // Cleanup
//! # let _ = std::fs::remove_file(&tmp_path);
//! #
//! # // For documentation purposes, show it as:
//! # /*
//! let db = Database::from("threats.db").open()?;
//!
//! // Automatic IP detection
//! if let Some(result) = db.lookup("1.2.3.4")? {
//!     println!("Found: {:?}", result);
//! }
//!
//! // Automatic pattern matching
//! if let Some(result) = db.lookup("malware.evil.com")? {
//!     println!("Matches pattern: {:?}", result);
//! }
//! # */
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Key Features
//!
//! - **Unified Queries**: Automatically detects IP addresses vs patterns
//! - **Rich Data**: Store JSON-like structured data with each entry
//! - **Zero-Copy Loading**: Memory-mapped files load instantly (~1ms)
//! - **MMDB Compatible**: Drop-in replacement for libmaxminddb
//! - **Shared Memory**: Multiple processes share physical RAM
//! - **C/C++ API**: Stable FFI for any language
//! - **Fast Lookups**: O(log n) for IPs, O(n) for patterns
//!
//! # Architecture
//!
//! Matchy uses a hybrid binary format combining IP tree structures with
//! pattern matching automata:
//!
//! ```text
//! ┌──────────────────────────────────────┐
//! │  Database File Format                │
//! ├──────────────────────────────────────┤
//! │  1. IP Search Tree (binary trie)     │
//! │  2. Data Section (deduplicated)      │
//! │  3. Pattern Matcher (Aho-Corasick)   │
//! │  4. Metadata                         │
//! └──────────────────────────────────────┘
//!          ↓ mmap() syscall (~1ms)
//! ┌──────────────────────────────────────┐
//! │  Memory (read-only, shared)          │
//! │  Ready for queries immediately!      │
//! └──────────────────────────────────────┘
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

// Module declarations

// Public modules (documented API)
/// Unified database API
pub mod database;
/// Error types for Paraglob operations
pub mod error;
/// Fast extraction of structured patterns (domains, IPs, emails) from text
///
/// Re-exported from matchy-extractor crate for convenience.
pub use matchy_extractor as extractor;
/// File reading utilities with automatic gzip decompression
pub mod file_reader;
/// MISP JSON threat intelligence importer
pub mod misp_importer;

// Re-export format modules from matchy-format
/// MMDB format implementation (internal)
use matchy_format::mmdb;
/// Unified MMDB builder
pub use matchy_format::mmdb_builder;
/// Offset format structures
pub use matchy_format::offset_format;
/// Literal string hash table for O(1) exact matching
pub use matchy_literal_hash as literal_hash;

/// Batch processing infrastructure for efficient file analysis
///
/// General-purpose building blocks for sequential or parallel line-oriented processing:
/// - `LineFileReader` - Chunks files with gzip support
/// - `Worker` - Processes batches with extraction + matching  
/// - `LineBatch`, `MatchResult`, `LineMatch` - Data structures
pub mod processing;
#[cfg(feature = "bench-internal")]
pub mod serialization;
/// SIMD-accelerated utilities for pattern matching
///
/// Provides optimized implementations of common operations using SIMD instructions:
/// - ASCII lowercase conversion (4-8x faster than iterator chains)
/// - Byte searching and comparison
pub mod simd_utils;
/// Database validation for untrusted files
///
/// Provides comprehensive validation of `.mxy` database files including:
/// - **Standard**: All offsets, UTF-8 validation, basic structure
/// - **Strict**: Deep graph analysis, cycles, redundancy checks
pub mod validation;

/// Auto-reloading database wrapper (native platforms only)
///
/// Provides automatic file watching and hot-reload capability for production
/// deployments where database files may be updated while the application runs.
#[cfg(not(target_family = "wasm"))]
pub mod watching_database;

// Public C API (native platforms only - FFI not available on WASM)
#[cfg(not(target_family = "wasm"))]
pub mod c_api;

// Bench-only internal API surface (kept out of public builds)
#[cfg(feature = "bench-internal")]
#[doc(hidden)]
pub mod bench_api {
    pub use matchy_paraglob::{Paraglob, ParaglobBuilder};
}

// Re-exports for Rust consumers

/// Unified database for IP and pattern lookups
pub use crate::database::{
    Database, DatabaseError, DatabaseOpener, DatabaseOptions, DatabaseStats, QueryResult,
};

/// Data value type for database entries
pub use matchy_data_format::DataValue;

/// Main error type for matchy operations
pub use crate::error::{MatchyError, Result};
/// Match mode for text operations (case sensitive/insensitive)
pub use matchy_match_mode::MatchMode;

// Re-export component error types for advanced users
pub use crate::error::{FormatError, ParaglobError};

/// Auto-reloading database wrapper (native platforms only)
///
/// Provides [`WatchingDatabase`] which wraps a [`Database`] and automatically
/// reloads it when the file changes. Available on all platforms except WASM.
#[cfg(not(target_family = "wasm"))]
pub use crate::watching_database::{ReloadCallback, ReloadEvent, WatchingDatabase};

/// Unified database builder for creating databases with IP addresses and patterns
///
/// This is the primary API for building databases. It automatically detects whether
/// entries are IP addresses (including CIDRs) or glob patterns and handles them appropriately.
///
/// # Example
/// ```rust,no_run
/// use matchy::{DatabaseBuilder, MatchMode};
/// use std::collections::HashMap;
/// use matchy::DataValue;
///
/// let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
///
/// // Add IP entries
/// let mut data = HashMap::new();
/// data.insert("threat_level".to_string(), DataValue::String("high".to_string()));
/// builder.add_entry("1.2.3.4", data)?;
///
/// // Add pattern entries
/// let mut data = HashMap::new();
/// data.insert("category".to_string(), DataValue::String("malware".to_string()));
/// builder.add_entry("*.evil.com", data)?;
///
/// // Build and save
/// let db_bytes = builder.build()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub use matchy_format::mmdb_builder::DatabaseBuilder;

/// Entry type classification for database builder
///
/// Represents whether an entry should be treated as an IP address, literal string,
/// or glob pattern. Used with [`DatabaseBuilder::detect_entry_type`] for explicit
/// type control.
pub use matchy_format::mmdb_builder::EntryType;

// Version information
/// Library version string
pub const MATCHY_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library major version
pub const MATCHY_VERSION_MAJOR: &str = env!("CARGO_PKG_VERSION_MAJOR");

/// Library minor version
pub const MATCHY_VERSION_MINOR: &str = env!("CARGO_PKG_VERSION_MINOR");

/// Library patch version
pub const MATCHY_VERSION_PATCH: &str = env!("CARGO_PKG_VERSION_PATCH");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        // Verify version components parse as valid numbers
        assert!(MATCHY_VERSION_MAJOR.parse::<u32>().is_ok());
        assert!(MATCHY_VERSION_MINOR.parse::<u32>().is_ok());
        assert!(MATCHY_VERSION_PATCH.parse::<u32>().is_ok());

        // Verify full version matches format
        let expected = format!(
            "{}.{}.{}",
            MATCHY_VERSION_MAJOR, MATCHY_VERSION_MINOR, MATCHY_VERSION_PATCH
        );
        assert_eq!(MATCHY_VERSION, expected);
    }
}
