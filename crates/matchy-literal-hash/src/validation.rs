//! Literal hash table validation for untrusted binary data
//!
//! This module validates literal hash table structures to ensure they are safe to use.
//! Validates header, magic bytes, version, and basic structural integrity.

use crate::{LiteralHashHeader, LITERAL_HASH_MAGIC, MATCHY_LITERAL_HASH_VERSION};

/// Validation result for literal hash structures
#[derive(Debug, Clone)]
pub struct LiteralHashValidationResult {
    /// Critical errors that make the structure unusable
    pub errors: Vec<String>,
    /// Warnings about potential issues (non-fatal)
    pub warnings: Vec<String>,
    /// Statistics gathered during validation
    pub stats: LiteralHashStats,
}

/// Statistics gathered during literal hash validation
#[derive(Debug, Clone, Default)]
pub struct LiteralHashStats {
    /// Number of literal patterns
    pub entry_count: u32,
    /// Hash table size
    pub table_size: u32,
    /// Version number
    pub version: u32,
}

impl LiteralHashValidationResult {
    fn new() -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
            stats: LiteralHashStats::default(),
        }
    }

    /// Check if validation passed (no errors)
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validate literal hash section structure
///
/// Validates:
/// - MMDB_LITERAL marker (if present before the data)
/// - LHSH magic bytes
/// - Header structure and fields
/// - Version validity
/// - Entry count and table size sanity
///
/// # Arguments
///
/// * `buffer` - The buffer containing the entire database
/// * `offset` - Offset to the literal hash section (where LHSH magic starts)
///
/// # Returns
///
/// A `LiteralHashValidationResult` with errors, warnings, and statistics
pub fn validate_literal_hash(buffer: &[u8], offset: usize) -> LiteralHashValidationResult {
    let mut result = LiteralHashValidationResult::new();

    // Check for "MMDB_LITERAL" marker (16 bytes before the hash data)
    const LITERAL_MARKER: &[u8] = b"MMDB_LITERAL\x00\x00\x00\x00";

    if offset >= 16 && offset - 16 <= buffer.len() {
        let marker_start = offset - 16;
        if marker_start + 16 <= buffer.len() {
            let marker = &buffer[marker_start..marker_start + 16];
            if marker != LITERAL_MARKER {
                result
                    .warnings
                    .push("MMDB_LITERAL marker not found at expected location".to_string());
            }
        }
    }

    // Check for LHSH magic bytes
    if offset + 4 > buffer.len() {
        result
            .errors
            .push("Literal hash section truncated (no magic bytes)".to_string());
        return result;
    }

    let magic = &buffer[offset..offset + 4];
    if magic != LITERAL_HASH_MAGIC {
        result.errors.push(format!(
            "Invalid literal hash magic: expected LHSH, got {:?}",
            String::from_utf8_lossy(magic)
        ));
        return result;
    }

    // Read and validate header
    if offset + std::mem::size_of::<LiteralHashHeader>() > buffer.len() {
        result
            .errors
            .push("Literal hash header truncated".to_string());
        return result;
    }

    // Read header fields manually (safer than casting)
    let version = u32::from_le_bytes([
        buffer[offset + 4],
        buffer[offset + 5],
        buffer[offset + 6],
        buffer[offset + 7],
    ]);
    let entry_count = u32::from_le_bytes([
        buffer[offset + 8],
        buffer[offset + 9],
        buffer[offset + 10],
        buffer[offset + 11],
    ]);
    let table_size = u32::from_le_bytes([
        buffer[offset + 12],
        buffer[offset + 13],
        buffer[offset + 14],
        buffer[offset + 15],
    ]);

    result.stats.version = version;
    result.stats.entry_count = entry_count;
    result.stats.table_size = table_size;

    // Validate version
    if version != MATCHY_LITERAL_HASH_VERSION {
        result.warnings.push(format!(
            "Unexpected literal hash version: {} (expected {})",
            version, MATCHY_LITERAL_HASH_VERSION
        ));
    }

    // Sanity check: very large entry counts
    if entry_count > 10_000_000 {
        result.warnings.push(format!(
            "Very large literal count: {} (> 10M, potential memory issue)",
            entry_count
        ));
    }

    // Sanity check: table size should be >= entry count
    if table_size < entry_count {
        result.errors.push(format!(
            "Table size {} is smaller than entry count {}",
            table_size, entry_count
        ));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_literal_hash_truncated() {
        let buffer = vec![0u8; 10]; // Too small
        let result = validate_literal_hash(&buffer, 0);
        assert!(!result.is_valid());
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_validate_literal_hash_bad_magic() {
        let mut buffer = vec![0u8; 100];
        buffer[0..4].copy_from_slice(b"XXXX"); // Bad magic
        let result = validate_literal_hash(&buffer, 0);
        assert!(!result.is_valid());
        assert!(result.errors.iter().any(|e| e.contains("magic")));
    }

    #[test]
    fn test_validate_literal_hash_valid() {
        let mut buffer = vec![0u8; 100];
        buffer[0..4].copy_from_slice(b"LHSH"); // Valid magic
        buffer[4..8].copy_from_slice(&1u32.to_le_bytes()); // version = 1
        buffer[8..12].copy_from_slice(&100u32.to_le_bytes()); // entry_count = 100
        buffer[12..16].copy_from_slice(&128u32.to_le_bytes()); // table_size = 128

        let result = validate_literal_hash(&buffer, 0);
        assert!(result.is_valid());
        assert_eq!(result.stats.version, 1);
        assert_eq!(result.stats.entry_count, 100);
        assert_eq!(result.stats.table_size, 128);
    }

    #[test]
    fn test_validate_literal_hash_table_too_small() {
        let mut buffer = vec![0u8; 100];
        buffer[0..4].copy_from_slice(b"LHSH");
        buffer[4..8].copy_from_slice(&1u32.to_le_bytes()); // version
        buffer[8..12].copy_from_slice(&100u32.to_le_bytes()); // entry_count = 100
        buffer[12..16].copy_from_slice(&50u32.to_le_bytes()); // table_size = 50 (too small!)

        let result = validate_literal_hash(&buffer, 0);
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("smaller than entry count")));
    }
}
