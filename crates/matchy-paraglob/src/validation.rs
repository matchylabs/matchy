//! Paraglob validation for untrusted binary data
//!
//! This module validates paraglob pattern structures and their relationships to ensure
//! they are safe to use. Validates pattern entries, AC literal mappings, meta-word mappings,
//! and cross-references between patterns and AC nodes.

use crate::offset_format::{MetaWordMapping, PatternEntry};
use std::collections::HashSet;
use std::mem;
use zerocopy::FromBytes;

/// Validation result for paraglob structures
#[derive(Debug, Clone)]
pub struct ParaglobValidationResult {
    /// Critical errors that make the structure unusable
    pub errors: Vec<String>,
    /// Warnings about potential issues (non-fatal)
    pub warnings: Vec<String>,
    /// Statistics gathered during validation
    pub stats: ParaglobStats,
}

/// Statistics gathered during paraglob validation
#[derive(Debug, Clone, Default)]
pub struct ParaglobStats {
    /// Number of patterns
    pub pattern_count: u32,
    /// Number of literal patterns
    pub literal_count: u32,
    /// Number of glob patterns
    pub glob_count: u32,
    /// Number of AC literal mapping entries validated
    pub ac_literal_map_entries: u32,
    /// Number of meta-word mappings
    pub meta_word_count: u32,
    /// Number of unreferenced literal patterns
    pub unreferenced_literals: u32,
}

impl ParaglobValidationResult {
    fn new() -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
            stats: ParaglobStats::default(),
        }
    }

    /// Check if validation passed (no errors)
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validate pattern entries
///
/// Validates:
/// - Pattern entry bounds
/// - Pattern type validity (literal vs glob)
/// - Pattern ID consistency
///
/// # Arguments
///
/// * `buffer` - The buffer containing paraglob data
/// * `patterns_offset` - Offset to the pattern entries array
/// * `pattern_count` - Number of patterns
///
/// # Returns
///
/// A `ParaglobValidationResult` with errors, warnings, and statistics
pub fn validate_patterns(
    buffer: &[u8],
    patterns_offset: usize,
    pattern_count: usize,
) -> ParaglobValidationResult {
    let mut result = ParaglobValidationResult::new();
    result.stats.pattern_count = pattern_count as u32;

    if pattern_count == 0 {
        return result;
    }

    let mut literal_count = 0;
    let mut glob_count = 0;

    for i in 0..pattern_count {
        let entry_offset = patterns_offset + i * mem::size_of::<PatternEntry>();

        if entry_offset + mem::size_of::<PatternEntry>() > buffer.len() {
            result
                .errors
                .push(format!("Pattern entry {} out of bounds", i));
            continue;
        }

        let entry = match PatternEntry::read_from_prefix(&buffer[entry_offset..]) {
            Ok((e, _)) => e,
            Err(_) => {
                result
                    .errors
                    .push(format!("Failed to read pattern entry {}", i));
                continue;
            }
        };

        // Validate pattern type
        match entry.pattern_type {
            0 => literal_count += 1, // Literal
            1 => glob_count += 1,    // Glob
            t => result
                .errors
                .push(format!("Pattern {} has invalid type: {}", i, t)),
        }

        // Pattern ID should match index (typically)
        if entry.pattern_id != i as u32 {
            result.warnings.push(format!(
                "Pattern {} has mismatched ID: {} (expected {})",
                i, entry.pattern_id, i
            ));
        }
    }

    result.stats.literal_count = literal_count;
    result.stats.glob_count = glob_count;

    result
}

/// Build pattern info list for cross-validation with AC
///
/// Creates a list of (pattern_id, pattern_type) tuples that can be passed
/// to matchy_ac::validate_pattern_references for cross-validation.
/// This avoids matchy-paraglob needing to read AC node structures.
///
/// # Arguments
///
/// * `buffer` - The buffer containing paraglob data
/// * `patterns_offset` - Offset to the pattern entries array
/// * `pattern_count` - Number of patterns
///
/// # Returns
///
/// A vector of (pattern_id, pattern_type) tuples, or an error
pub fn build_pattern_info(
    buffer: &[u8],
    patterns_offset: usize,
    pattern_count: usize,
) -> Result<Vec<(u32, u8)>, String> {
    let mut pattern_info = Vec::with_capacity(pattern_count);

    for i in 0..pattern_count {
        let entry_offset = patterns_offset + i * mem::size_of::<PatternEntry>();
        if entry_offset + mem::size_of::<PatternEntry>() > buffer.len() {
            return Err(format!("Pattern entry {} out of bounds", i));
        }

        let entry = match PatternEntry::read_from_prefix(&buffer[entry_offset..]) {
            Ok((e, _)) => e,
            Err(_) => return Err(format!("Failed to read pattern entry {}", i)),
        };

        pattern_info.push((entry.pattern_id, entry.pattern_type));
    }

    Ok(pattern_info)
}

/// Validate AC literal mapping consistency
///
/// Validates the AC literal mapping structure (v3+ format).
/// Checks entry counts, pattern ID references, and structure integrity.
///
/// # Arguments
///
/// * `buffer` - The buffer containing paraglob data
/// * `map_offset` - Offset to the AC literal mapping
/// * `pattern_count` - Total number of patterns (for validating pattern IDs)
///
/// # Returns
///
/// A `ParaglobValidationResult` with errors, warnings, and statistics
pub fn validate_ac_literal_mapping(
    buffer: &[u8],
    map_offset: usize,
    pattern_count: u32,
) -> ParaglobValidationResult {
    let mut result = ParaglobValidationResult::new();

    if map_offset + 4 > buffer.len() {
        result
            .errors
            .push("AC literal mapping header truncated".to_string());
        return result;
    }

    // Read entry count
    let entry_count = u32::from_le_bytes([
        buffer[map_offset],
        buffer[map_offset + 1],
        buffer[map_offset + 2],
        buffer[map_offset + 3],
    ]) as usize;

    let mut current_offset = map_offset + 4;
    let mut referenced_patterns = HashSet::new();
    let mut entries_checked = 0;

    // Walk through variable-length entries
    for i in 0..entry_count {
        // Each entry: [literal_id: u32][pattern_count: u32][pattern_ids: u32...]
        if current_offset + 8 > buffer.len() {
            result.warnings.push(format!(
                "AC literal mapping truncated at entry {} of {}",
                i, entry_count
            ));
            break;
        }

        let _literal_id = u32::from_le_bytes([
            buffer[current_offset],
            buffer[current_offset + 1],
            buffer[current_offset + 2],
            buffer[current_offset + 3],
        ]);

        let pattern_count_entry = u32::from_le_bytes([
            buffer[current_offset + 4],
            buffer[current_offset + 5],
            buffer[current_offset + 6],
            buffer[current_offset + 7],
        ]);

        current_offset += 8;

        // Read pattern IDs
        let pattern_ids_size = (pattern_count_entry as usize) * 4;
        if current_offset + pattern_ids_size > buffer.len() {
            result.warnings.push(format!(
                "AC literal mapping entry {} pattern IDs truncated",
                i
            ));
            break;
        }

        for j in 0..pattern_count_entry {
            let pid_offset = current_offset + (j as usize) * 4;
            let pattern_id = u32::from_le_bytes([
                buffer[pid_offset],
                buffer[pid_offset + 1],
                buffer[pid_offset + 2],
                buffer[pid_offset + 3],
            ]);

            if pattern_id >= pattern_count {
                result.errors.push(format!(
                    "AC literal mapping entry {} references invalid pattern ID: {}",
                    i, pattern_id
                ));
            } else {
                referenced_patterns.insert(pattern_id);
            }
        }

        current_offset += pattern_ids_size;
        entries_checked += 1;
    }

    result.stats.ac_literal_map_entries = entries_checked as u32;

    result
}

/// Validate meta-word mappings
///
/// Validates meta-word mapping structures.
/// Checks string offsets, pattern ID arrays, and reference validity.
///
/// # Arguments
///
/// * `buffer` - The buffer containing paraglob data
/// * `mapping_offset` - Offset to the meta-word mappings array
/// * `mapping_count` - Number of meta-word mappings
/// * `pattern_count` - Total number of patterns (for validating pattern IDs)
///
/// # Returns
///
/// A `ParaglobValidationResult` with errors, warnings, and statistics
pub fn validate_meta_word_mappings(
    buffer: &[u8],
    mapping_offset: usize,
    mapping_count: usize,
    pattern_count: u32,
) -> ParaglobValidationResult {
    let mut result = ParaglobValidationResult::new();
    result.stats.meta_word_count = mapping_count as u32;

    let mut referenced_patterns = HashSet::new();
    let mut invalid_references = 0;

    for i in 0..mapping_count {
        let entry_offset = mapping_offset + i * mem::size_of::<MetaWordMapping>();
        if entry_offset + mem::size_of::<MetaWordMapping>() > buffer.len() {
            result
                .errors
                .push(format!("Meta-word mapping {} out of bounds", i));
            continue;
        }

        let mapping = match MetaWordMapping::read_from_prefix(&buffer[entry_offset..]) {
            Ok((m, _)) => m,
            Err(_) => {
                result
                    .errors
                    .push(format!("Failed to read meta-word mapping {}", i));
                continue;
            }
        };

        // Validate meta-word string offset
        if mapping.meta_word_offset as usize >= buffer.len() {
            invalid_references += 1;
        }

        // Validate pattern IDs array offset and count
        if mapping.pattern_count > 0 {
            let pattern_ids_size = (mapping.pattern_count as usize) * mem::size_of::<u32>();
            let pattern_ids_offset = mapping.pattern_ids_offset as usize;

            if pattern_ids_offset + pattern_ids_size <= buffer.len() {
                // Read and validate each pattern ID
                for j in 0..mapping.pattern_count {
                    let pid_offset = pattern_ids_offset + (j as usize) * mem::size_of::<u32>();
                    if pid_offset + 4 <= buffer.len() {
                        let pattern_id = u32::from_le_bytes([
                            buffer[pid_offset],
                            buffer[pid_offset + 1],
                            buffer[pid_offset + 2],
                            buffer[pid_offset + 3],
                        ]);

                        if pattern_id >= pattern_count {
                            invalid_references += 1;
                        } else {
                            referenced_patterns.insert(pattern_id);
                        }
                    }
                }
            } else {
                invalid_references += 1;
            }
        }
    }

    if invalid_references > 0 {
        result.errors.push(format!(
            "Meta-word mappings contain {} invalid references",
            invalid_references
        ));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_patterns() {
        let buffer = vec![0u8; 100];
        let result = validate_patterns(&buffer, 0, 0);
        assert!(result.is_valid());
        assert_eq!(result.stats.pattern_count, 0);
    }

    #[test]
    fn test_validate_patterns_out_of_bounds() {
        let buffer = vec![0u8; 10]; // Too small
        let result = validate_patterns(&buffer, 0, 1);
        assert!(!result.is_valid());
        assert!(!result.errors.is_empty());
    }
}
