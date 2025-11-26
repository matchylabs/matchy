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
/// Validates the AC literal mapping structure (v3+ format - hash table).
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

    // Load the hash table and validate it
    let hash_buffer = &buffer[map_offset..];
    if let Err(e) = crate::literal_hash::ACLiteralHash::from_buffer(hash_buffer) {
        result
            .errors
            .push(format!("Failed to load AC literal hash table: {}", e));
        return result;
    }

    // Validate all pattern IDs in the hash table
    // We need to walk through the hash table entries and check pattern lists
    let header_size = mem::size_of::<crate::literal_hash::ACLiteralHashHeader>();
    let table_start = map_offset + header_size;
    let entry_size = mem::size_of::<crate::literal_hash::ACHashEntry>();

    // Read header to get table size
    if hash_buffer.len() < header_size {
        result
            .errors
            .push("AC literal hash header truncated".to_string());
        return result;
    }

    let table_size = u32::from_le_bytes([
        hash_buffer[12],
        hash_buffer[13],
        hash_buffer[14],
        hash_buffer[15],
    ]) as usize;

    let patterns_start_in_hash = u32::from_le_bytes([
        hash_buffer[16],
        hash_buffer[17],
        hash_buffer[18],
        hash_buffer[19],
    ]) as usize;

    let mut referenced_patterns = HashSet::new();
    let mut entries_validated = 0;

    // Walk through hash table entries
    for i in 0..table_size {
        let entry_offset = table_start - map_offset + i * entry_size;
        if entry_offset + entry_size > hash_buffer.len() {
            result
                .errors
                .push(format!("Hash table entry {} out of bounds", i));
            break;
        }

        let literal_id = u32::from_le_bytes([
            hash_buffer[entry_offset],
            hash_buffer[entry_offset + 1],
            hash_buffer[entry_offset + 2],
            hash_buffer[entry_offset + 3],
        ]);

        // Skip empty slots
        if literal_id == 0xFFFFFFFF {
            continue;
        }

        let patterns_offset = u32::from_le_bytes([
            hash_buffer[entry_offset + 4],
            hash_buffer[entry_offset + 5],
            hash_buffer[entry_offset + 6],
            hash_buffer[entry_offset + 7],
        ]) as usize;

        let pattern_count_entry = u32::from_le_bytes([
            hash_buffer[entry_offset + 8],
            hash_buffer[entry_offset + 9],
            hash_buffer[entry_offset + 10],
            hash_buffer[entry_offset + 11],
        ]) as usize;

        // Validate pattern IDs
        let abs_patterns_offset = patterns_start_in_hash + patterns_offset;
        for j in 0..pattern_count_entry {
            let pid_offset = abs_patterns_offset + j * 4;
            if pid_offset + 4 > hash_buffer.len() {
                result.errors.push(format!(
                    "Pattern list for literal {} truncated at pattern {}",
                    literal_id, j
                ));
                break;
            }

            let pattern_id = u32::from_le_bytes([
                hash_buffer[pid_offset],
                hash_buffer[pid_offset + 1],
                hash_buffer[pid_offset + 2],
                hash_buffer[pid_offset + 3],
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

        entries_validated += 1;
    }

    result.stats.ac_literal_map_entries = entries_validated;

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

/// Get pattern data offsets for cross-component validation
///
/// Extracts all data_offset values from PatternDataMapping entries.
/// These are FILE-ABSOLUTE offsets pointing to the MMDB data section.
/// matchy-format validates these offsets point to valid data.
///
/// # Arguments
///
/// * `buffer` - The PARAGLOB section buffer (starting at PARAGLOB magic)
/// * `header` - Already-parsed ParaglobHeader
///
/// # Returns
///
/// Vector of file-absolute data offsets, empty if no data mappings exist.
///
/// # Example
///
/// ```rust,ignore
/// // matchy-format uses this to validate external references
/// let offsets = get_pattern_data_offsets(paraglob_buffer, &header)?;
/// for offset in offsets {
///     validate_offset_in_data_section(offset, data_start, data_end)?;
/// }
/// ```
pub fn get_pattern_data_offsets(
    buffer: &[u8],
    header: &crate::offset_format::ParaglobHeader,
) -> Result<Vec<u32>, String> {
    // Check if this PARAGLOB section has data mappings
    if !header.has_data_section() || header.mapping_count == 0 {
        return Ok(Vec::new()); // No external references
    }

    let mappings_offset = header.mapping_table_offset as usize;
    let mapping_count = header.mapping_count as usize;
    let mapping_size = mem::size_of::<crate::offset_format::PatternDataMapping>();

    // Validate mappings are within buffer
    if mappings_offset + mapping_count * mapping_size > buffer.len() {
        return Err("Pattern data mappings extend beyond buffer".to_string());
    }

    let mut offsets = Vec::with_capacity(mapping_count);

    // Read each PatternDataMapping and extract data_offset
    for i in 0..mapping_count {
        let mapping_offset = mappings_offset + i * mapping_size;
        let mapping_bytes = &buffer[mapping_offset..];

        let (mapping, _) = crate::offset_format::PatternDataMapping::read_from_prefix(
            mapping_bytes,
        )
        .map_err(|_| {
            format!(
                "Failed to read PatternDataMapping at offset {}",
                mapping_offset
            )
        })?;

        // Extract just the data_offset field (the yield value)
        offsets.push(mapping.data_offset);
    }

    Ok(offsets)
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

    #[test]
    fn test_get_pattern_data_offsets_no_mappings() {
        // Create a minimal valid header with no data section
        let mut buffer = vec![0u8; mem::size_of::<crate::offset_format::ParaglobHeader>()];
        let magic = b"PARAGLOB";
        buffer[..8].copy_from_slice(magic);

        let header = crate::offset_format::ParaglobHeader::read_from_prefix(&buffer)
            .unwrap()
            .0;
        let result = get_pattern_data_offsets(&buffer, &header);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }
}
