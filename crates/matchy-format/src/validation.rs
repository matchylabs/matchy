//! Validation for matchy format file structure
//!
//! Provides validation of pattern-to-data mappings and other format-level
//! consistency checks.

use crate::{ParaglobHeader, PatternDataMapping};
use matchy_data_format::DataValue;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use zerocopy::FromBytes;

/// Trait for validating entry data before insertion into a database
///
/// Implement this trait to provide custom validation logic for entries
/// being added to a [`DatabaseBuilder`](crate::DatabaseBuilder).
///
/// # Example
///
/// ```rust,ignore
/// use matchy_format::{DatabaseBuilder, EntryValidator};
/// use matchy_data_format::DataValue;
/// use std::collections::HashMap;
/// use std::error::Error;
///
/// struct RequiredFieldValidator {
///     required_fields: Vec<String>,
/// }
///
/// impl EntryValidator for RequiredFieldValidator {
///     fn validate(
///         &self,
///         key: &str,
///         data: &HashMap<String, DataValue>,
///     ) -> Result<(), Box<dyn Error + Send + Sync>> {
///         for field in &self.required_fields {
///             if !data.contains_key(field) {
///                 return Err(format!(
///                     "Entry '{}': missing required field '{}'",
///                     key, field
///                 ).into());
///             }
///         }
///         Ok(())
///     }
/// }
///
/// let validator = RequiredFieldValidator {
///     required_fields: vec!["threat_level".to_string(), "source".to_string()],
/// };
///
/// let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive)
///     .with_validator(Box::new(validator));
///
/// // This will fail validation
/// builder.add_entry("1.2.3.4", HashMap::new())?;
/// ```
pub trait EntryValidator: Send + Sync {
    /// Validate entry data before insertion
    ///
    /// # Arguments
    /// * `key` - The entry key (IP, domain, pattern, etc.)
    /// * `data` - The data map to be associated with this entry
    ///
    /// # Returns
    /// * `Ok(())` if validation passes
    /// * `Err(...)` with a descriptive error message if validation fails
    fn validate(
        &self,
        key: &str,
        data: &HashMap<String, DataValue>,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;
}

/// Validation result for format-level checks
#[derive(Debug, Clone)]
pub struct FormatValidationResult {
    /// Errors found during validation
    pub errors: Vec<String>,
    /// Warnings about potential issues
    pub warnings: Vec<String>,
    /// Validation statistics
    pub stats: FormatStats,
}

impl FormatValidationResult {
    /// Create a new empty validation result
    pub fn new() -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
            stats: FormatStats::default(),
        }
    }

    /// Check if validation passed (no errors)
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Add an error
    pub fn error(&mut self, msg: String) {
        self.errors.push(msg);
    }

    /// Add a warning
    pub fn warning(&mut self, msg: String) {
        self.warnings.push(msg);
    }
}

impl Default for FormatValidationResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics from format validation
#[derive(Debug, Clone, Default)]
pub struct FormatStats {
    /// Number of mappings validated
    pub mappings_validated: usize,
    /// Number of patterns with data
    pub patterns_with_data: usize,
    /// Number of duplicate mappings found
    pub duplicate_mappings: usize,
}

/// Validate data section mapping consistency (v2+ format)
///
/// This function validates the pattern→data mapping table to ensure:
/// - All pattern IDs are valid (< pattern_count)
/// - No duplicate pattern IDs in mapping table
/// - Data offsets and sizes are within bounds
///
/// # Arguments
/// * `buffer` - Full file buffer
/// * `header` - Parsed ParaglobHeader
///
/// # Returns
/// Validation result with errors, warnings, and coverage statistics
pub fn validate_data_mapping_consistency(
    buffer: &[u8],
    header: &ParaglobHeader,
) -> FormatValidationResult {
    let mut result = FormatValidationResult::new();

    let mapping_offset = header.mapping_table_offset as usize;
    let mapping_count = header.mapping_count as usize;
    let data_offset = header.data_section_offset as usize;
    let data_size = header.data_section_size as usize;

    if mapping_count == 0 {
        // No mappings is valid (not all patterns need data)
        return result;
    }

    if mapping_offset == 0 {
        result.warning("Mapping table offset is 0 but mapping_count > 0".to_string());
        return result;
    }

    let mut patterns_with_data = HashSet::new();
    let mut duplicate_mappings = 0;

    for i in 0..mapping_count {
        let entry_offset = mapping_offset + i * std::mem::size_of::<PatternDataMapping>();
        if entry_offset + std::mem::size_of::<PatternDataMapping>() > buffer.len() {
            result.error(format!(
                "Mapping entry {} at offset {} truncated",
                i, entry_offset
            ));
            continue;
        }

        let mapping = match PatternDataMapping::read_from_prefix(&buffer[entry_offset..]) {
            Ok((m, _)) => m,
            Err(_) => {
                result.error(format!(
                    "Failed to read PatternDataMapping at offset {}",
                    entry_offset
                ));
                continue;
            }
        };

        // Check for duplicate pattern IDs in mapping table
        if !patterns_with_data.insert(mapping.pattern_id) {
            duplicate_mappings += 1;
        }

        // Validate pattern ID is valid
        if mapping.pattern_id >= header.pattern_count {
            result.error(format!(
                "Mapping entry {} references invalid pattern ID {} (max: {})",
                i,
                mapping.pattern_id,
                header.pattern_count - 1
            ));
            continue;
        }

        // Validate inline data bounds if applicable
        if header.has_inline_data() {
            let data_ref = mapping.data_offset as usize;
            // Check if this looks like an inline data reference
            if data_ref >= data_offset && data_ref < data_offset + data_size {
                let data_end = data_ref + mapping.data_size as usize;
                if data_end > data_offset + data_size {
                    result.error(format!(
                        "Mapping entry {} data range [{}, {}) exceeds data section [{}, {})",
                        i,
                        data_ref,
                        data_end,
                        data_offset,
                        data_offset + data_size
                    ));
                }
            }
        }

        result.stats.mappings_validated += 1;
    }

    result.stats.patterns_with_data = patterns_with_data.len();
    result.stats.duplicate_mappings = duplicate_mappings;

    if duplicate_mappings > 0 {
        result.warning(format!(
            "Found {} duplicate pattern IDs in data mapping table",
            duplicate_mappings
        ));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_header(pattern_count: u32, mapping_count: u32) -> ParaglobHeader {
        let mut header = ParaglobHeader::new();
        header.pattern_count = pattern_count;
        header.mapping_count = mapping_count;
        header.mapping_table_offset = 1000; // Arbitrary offset
        header.data_section_offset = 5000;
        header.data_section_size = 1000;
        header.data_flags = 0x01; // Inline data
        header
    }

    fn encode_mapping(pattern_id: u32, data_offset: u32, data_size: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&pattern_id.to_le_bytes());
        buf.extend_from_slice(&data_offset.to_le_bytes());
        buf.extend_from_slice(&data_size.to_le_bytes());
        buf
    }

    #[test]
    fn test_validate_no_mappings() {
        let header = create_test_header(10, 0);
        let buffer = vec![0u8; 6000];

        let result = validate_data_mapping_consistency(&buffer, &header);
        assert!(result.is_valid());
        assert_eq!(result.stats.mappings_validated, 0);
    }

    #[test]
    fn test_validate_valid_mappings() {
        let header = create_test_header(10, 3);
        let mut buffer = vec![0u8; 6000];

        // Write three valid mappings at offset 1000
        let mappings = vec![
            encode_mapping(0, 5100, 50),
            encode_mapping(1, 5200, 50),
            encode_mapping(2, 5300, 50),
        ];

        let mut offset = 1000;
        for mapping_bytes in mappings {
            buffer[offset..offset + mapping_bytes.len()].copy_from_slice(&mapping_bytes);
            offset += mapping_bytes.len();
        }

        let result = validate_data_mapping_consistency(&buffer, &header);
        assert!(result.is_valid());
        assert_eq!(result.stats.mappings_validated, 3);
        assert_eq!(result.stats.patterns_with_data, 3);
        assert_eq!(result.stats.duplicate_mappings, 0);
    }

    #[test]
    fn test_validate_duplicate_pattern_ids() {
        let header = create_test_header(10, 3);
        let mut buffer = vec![0u8; 6000];

        // Write mappings with duplicate pattern IDs
        let mappings = vec![
            encode_mapping(0, 5100, 50),
            encode_mapping(1, 5200, 50),
            encode_mapping(0, 5300, 50), // Duplicate!
        ];

        let mut offset = 1000;
        for mapping_bytes in mappings {
            buffer[offset..offset + mapping_bytes.len()].copy_from_slice(&mapping_bytes);
            offset += mapping_bytes.len();
        }

        let result = validate_data_mapping_consistency(&buffer, &header);
        assert!(result.is_valid()); // Duplicates are warnings, not errors
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(result.stats.duplicate_mappings, 1);
        assert_eq!(result.stats.patterns_with_data, 2); // Only 2 unique patterns
    }

    #[test]
    fn test_validate_invalid_pattern_id() {
        let header = create_test_header(10, 2);
        let mut buffer = vec![0u8; 6000];

        // Write mappings, one with invalid pattern ID
        let mappings = vec![
            encode_mapping(5, 5100, 50),
            encode_mapping(99, 5200, 50), // Invalid! >= pattern_count
        ];

        let mut offset = 1000;
        for mapping_bytes in mappings {
            buffer[offset..offset + mapping_bytes.len()].copy_from_slice(&mapping_bytes);
            offset += mapping_bytes.len();
        }

        let result = validate_data_mapping_consistency(&buffer, &header);
        assert!(!result.is_valid());
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].contains("invalid pattern ID 99"));
    }

    #[test]
    fn test_validate_data_bounds() {
        let header = create_test_header(10, 2);
        let mut buffer = vec![0u8; 6000];

        // Write mappings with out-of-bounds data
        let mappings = vec![
            encode_mapping(0, 5100, 50),  // Valid
            encode_mapping(1, 5900, 200), // Exceeds data section (5000 + 1000 = 6000)
        ];

        let mut offset = 1000;
        for mapping_bytes in mappings {
            buffer[offset..offset + mapping_bytes.len()].copy_from_slice(&mapping_bytes);
            offset += mapping_bytes.len();
        }

        let result = validate_data_mapping_consistency(&buffer, &header);
        assert!(!result.is_valid());
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].contains("exceeds data section"));
    }

    #[test]
    fn test_validate_truncated_mapping_table() {
        let header = create_test_header(10, 3);
        let buffer = vec![0u8; 1020]; // Too small to hold all 3 mappings

        let result = validate_data_mapping_consistency(&buffer, &header);
        assert!(!result.is_valid());
        assert!(result.errors.iter().any(|e| e.contains("truncated")));
    }
}
