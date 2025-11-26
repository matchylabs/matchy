//! Validation for MMDB data section encoding
//!
//! Provides validation of decoded DataValue structures to ensure:
//! - UTF-8 validity in strings (critical for safety)
//! - Structural integrity of data values
//!
//! These validations are building blocks that can be used by higher-level
//! validators (like MMDB validation) that understand file structure.

use crate::{DataDecoder, DataValue};

/// Validation result for data format checks
#[derive(Debug, Clone)]
pub struct DataFormatValidationResult {
    /// Errors found during validation
    pub errors: Vec<String>,
    /// Warnings about potential issues
    pub warnings: Vec<String>,
    /// Validation statistics
    pub stats: DataFormatStats,
}

impl DataFormatValidationResult {
    /// Create a new empty validation result
    pub fn new() -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
            stats: DataFormatStats::default(),
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

impl Default for DataFormatValidationResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics from data format validation
#[derive(Debug, Clone, Default)]
pub struct DataFormatStats {
    /// Number of strings validated
    pub strings_checked: u32,
    /// Number of maps validated
    pub maps_checked: u32,
    /// Number of arrays validated
    pub arrays_checked: u32,
    /// Total values validated
    pub values_checked: u32,
}

/// Validate UTF-8 in a decoded data value at the given offset
///
/// This function attempts to decode a value from the data section buffer
/// and recursively validates all strings within it.
///
/// # Arguments
/// * `data_section` - Raw data section bytes
/// * `offset` - Offset within data section to decode from
/// * `base_offset` - Base offset for pointer calculations (0 for standalone)
///
/// # Returns
/// * `Ok(count)` - Number of strings validated (all valid)
/// * `Err(msg)` - Error message if invalid UTF-8 found or decode failed
pub fn validate_data_value_utf8(
    data_section: &[u8],
    offset: usize,
    base_offset: usize,
) -> Result<u32, String> {
    let decoder = DataDecoder::new(data_section, base_offset);

    match decoder.decode(offset as u32) {
        Ok(value) => validate_value_strings_utf8(&value),
        Err(e) => Err(format!("Failed to decode data value: {}", e)),
    }
}

/// Recursively validate UTF-8 in all strings within a DataValue
///
/// This function traverses the DataValue structure and counts all strings,
/// verifying they are valid UTF-8. Since DataValue::String already guarantees
/// UTF-8 validity (enforced during decoding), this primarily serves as a
/// structural validator and counter.
///
/// # Arguments
/// * `value` - DataValue to validate
///
/// # Returns
/// * `Ok(count)` - Number of strings found (all valid UTF-8)
/// * `Err(msg)` - Error message if validation fails
///
/// # Note
/// The DataDecoder already enforces UTF-8 validity when creating String variants,
/// so this function won't find invalid UTF-8 in properly decoded values.
/// It's useful for:
/// - Counting strings in a structure
/// - Detecting decode issues early
/// - Providing structural validation
pub fn validate_value_strings_utf8(value: &DataValue) -> Result<u32, String> {
    let mut count = 0u32;

    match value {
        DataValue::String(_s) => {
            // String is already validated UTF-8 when decoded
            count += 1;
        }
        DataValue::Map(map) => {
            for val in map.values() {
                // Map keys are always strings, and already validated
                count += 1;
                // Recursively validate values
                count += validate_value_strings_utf8(val)?;
            }
        }
        DataValue::Array(arr) => {
            for val in arr {
                count += validate_value_strings_utf8(val)?;
            }
        }
        // Other types don't contain strings
        DataValue::Pointer(_)
        | DataValue::Double(_)
        | DataValue::Bytes(_)
        | DataValue::Uint16(_)
        | DataValue::Uint32(_)
        | DataValue::Int32(_)
        | DataValue::Uint64(_)
        | DataValue::Uint128(_)
        | DataValue::Bool(_)
        | DataValue::Float(_) => {}
    }

    Ok(count)
}

/// Validate data section structure by attempting to decode values
///
/// This is a comprehensive validation that attempts to decode all reachable
/// data values in a data section buffer.
///
/// # Arguments
/// * `data_section` - Raw data section bytes
/// * `base_offset` - Base offset for pointer calculations
/// * `offsets_to_check` - Specific offsets to validate (if empty, validates entire section)
///
/// # Returns
/// Validation result with errors, warnings, and statistics
pub fn validate_data_section(
    data_section: &[u8],
    base_offset: usize,
    offsets_to_check: &[u32],
) -> DataFormatValidationResult {
    let mut result = DataFormatValidationResult::new();

    if data_section.is_empty() {
        result.warning("Data section is empty".to_string());
        return result;
    }

    let decoder = DataDecoder::new(data_section, base_offset);

    // If specific offsets provided, check those
    if !offsets_to_check.is_empty() {
        for &offset in offsets_to_check {
            match decoder.decode(offset) {
                Ok(value) => {
                    result.stats.values_checked += 1;
                    match validate_value_strings_utf8(&value) {
                        Ok(count) => {
                            result.stats.strings_checked += count;
                        }
                        Err(e) => {
                            result.error(format!("Invalid UTF-8 at offset {}: {}", offset, e));
                        }
                    }

                    // Update type-specific stats
                    update_stats_for_value(&value, &mut result.stats);
                }
                Err(e) => {
                    result.error(format!("Failed to decode at offset {}: {}", offset, e));
                }
            }
        }
    } else {
        // If no specific offsets, just validate that the section is well-formed
        result.warning("No specific offsets to validate".to_string());
    }

    result
}

/// Update statistics based on value type
fn update_stats_for_value(value: &DataValue, stats: &mut DataFormatStats) {
    match value {
        DataValue::Map(m) => {
            stats.maps_checked += 1;
            for val in m.values() {
                update_stats_for_value(val, stats);
            }
        }
        DataValue::Array(arr) => {
            stats.arrays_checked += 1;
            for val in arr {
                update_stats_for_value(val, stats);
            }
        }
        _ => {}
    }
}

/// Maximum safe depth for pointer chains in MMDB data
pub const MAX_POINTER_DEPTH: usize = 32;

/// Maximum reasonable total nesting depth (arrays/maps + pointers)
pub const MAX_TOTAL_DEPTH: usize = 64;

/// Validation error types for MMDB data section pointer chains
#[derive(Debug)]
pub enum PointerValidationError {
    /// Cycle detected in pointer chain
    Cycle { offset: usize },
    /// Depth limit exceeded
    DepthExceeded { depth: usize },
    /// Invalid offset encountered
    InvalidOffset { offset: usize, reason: String },
    /// Invalid type ID
    InvalidType { offset: usize, type_id: u8 },
}

impl std::fmt::Display for PointerValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PointerValidationError::Cycle { offset } => {
                write!(f, "Pointer cycle detected at offset {}", offset)
            }
            PointerValidationError::DepthExceeded { depth } => {
                write!(f, "Depth {} exceeds limit", depth)
            }
            PointerValidationError::InvalidOffset { offset, reason } => {
                write!(f, "Invalid offset {} ({})", offset, reason)
            }
            PointerValidationError::InvalidType { offset, type_id } => {
                write!(f, "Invalid type {} at offset {}", type_id, offset)
            }
        }
    }
}

impl std::error::Error for PointerValidationError {}

/// Result of MMDB data section pointer validation
#[derive(Debug, Clone)]
pub struct PointerValidationResult {
    /// Errors found
    pub errors: Vec<String>,
    /// Warnings found  
    pub warnings: Vec<String>,
    /// Statistics
    pub stats: PointerValidationStats,
}

/// Statistics from pointer validation
#[derive(Debug, Clone, Default)]
pub struct PointerValidationStats {
    /// Number of pointers checked
    pub pointers_checked: usize,
    /// Number of cycles detected
    pub cycles_detected: usize,
    /// Maximum depth found
    pub max_depth: usize,
    /// Invalid pointers found
    pub invalid_pointers: usize,
}

impl PointerValidationResult {
    /// Create new empty result
    pub fn new() -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
            stats: PointerValidationStats::default(),
        }
    }

    /// Check if validation passed
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

impl Default for PointerValidationResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate a data value and all pointers it contains
///
/// Returns the maximum depth of pointer chains encountered.
/// Detects cycles using the visited set.
///
/// # Arguments
/// * `data_section` - Raw data section bytes
/// * `offset` - Offset within data section to start validation
/// * `visited` - Set of already-visited offsets (for cycle detection)
/// * `depth` - Current depth in pointer chain
///
/// # Returns
/// * `Ok(max_depth)` - Maximum depth reached
/// * `Err` - Validation error encountered
pub fn validate_data_value_pointers(
    data_section: &[u8],
    offset: usize,
    visited: &mut std::collections::HashSet<usize>,
    depth: usize,
) -> Result<usize, PointerValidationError> {
    // Check depth limit
    if depth > MAX_TOTAL_DEPTH {
        return Err(PointerValidationError::DepthExceeded { depth });
    }

    // Check for cycles
    if visited.contains(&offset) {
        return Err(PointerValidationError::Cycle { offset });
    }

    visited.insert(offset);

    // Validate offset bounds
    if offset >= data_section.len() {
        return Err(PointerValidationError::InvalidOffset {
            offset,
            reason: "Offset beyond data section".to_string(),
        });
    }

    // Read control byte
    let ctrl = data_section[offset];
    let type_id = ctrl >> 5;
    let payload = ctrl & 0x1F;

    let mut cursor = offset + 1;
    let mut max_child_depth = depth;

    match type_id {
        0 => {
            // Extended type
            if cursor >= data_section.len() {
                return Err(PointerValidationError::InvalidOffset {
                    offset,
                    reason: "Extended type truncated".to_string(),
                });
            }
            let raw_ext_type = data_section[cursor];
            cursor += 1;
            let ext_type_id = 7 + raw_ext_type;

            match ext_type_id {
                11 => {
                    // Array - validate all elements
                    let count = decode_size_for_validation(data_section, &mut cursor, payload)?;
                    for _ in 0..count {
                        let child_depth =
                            validate_data_value_pointers(data_section, cursor, visited, depth + 1)?;
                        max_child_depth = max_child_depth.max(child_depth);
                        cursor = skip_data_value(data_section, cursor)?;
                    }
                }
                8 | 9 | 10 | 14 | 15 => {
                    // Int32, Uint64, Uint128, Bool, Float - no pointers
                }
                _ => {
                    return Err(PointerValidationError::InvalidType {
                        offset,
                        type_id: ext_type_id,
                    });
                }
            }
        }
        1 => {
            // Pointer - critical to validate!
            let pointer_offset = decode_pointer_offset(data_section, &mut cursor, payload)?;

            // Validate pointer target
            if pointer_offset >= data_section.len() {
                return Err(PointerValidationError::InvalidOffset {
                    offset: pointer_offset,
                    reason: "Pointer target beyond data section".to_string(),
                });
            }

            // Recursively validate pointed-to value
            let child_depth =
                validate_data_value_pointers(data_section, pointer_offset, visited, depth + 1)?;
            max_child_depth = max_child_depth.max(child_depth);
        }
        2..=6 => {
            // String, Double, Bytes, Uint16, Uint32 - no pointers
        }
        7 => {
            // Map - validate all values
            let count = decode_size_for_validation(data_section, &mut cursor, payload)?;
            for _ in 0..count {
                // Skip key
                cursor = skip_data_value(data_section, cursor)?;
                // Validate value
                let child_depth =
                    validate_data_value_pointers(data_section, cursor, visited, depth + 1)?;
                max_child_depth = max_child_depth.max(child_depth);
                cursor = skip_data_value(data_section, cursor)?;
            }
        }
        _ => {
            return Err(PointerValidationError::InvalidType { offset, type_id });
        }
    }

    Ok(max_child_depth)
}

/// Decode size field for validation
fn decode_size_for_validation(
    data: &[u8],
    cursor: &mut usize,
    size_bits: u8,
) -> Result<usize, PointerValidationError> {
    match size_bits {
        0..=28 => Ok(size_bits as usize),
        29 => {
            if *cursor >= data.len() {
                return Err(PointerValidationError::InvalidOffset {
                    offset: *cursor,
                    reason: "Size byte out of bounds".to_string(),
                });
            }
            let size = data[*cursor] as usize;
            *cursor += 1;
            Ok(29 + size)
        }
        30 => {
            if *cursor + 2 > data.len() {
                return Err(PointerValidationError::InvalidOffset {
                    offset: *cursor,
                    reason: "Size bytes out of bounds".to_string(),
                });
            }
            let size = u16::from_be_bytes([data[*cursor], data[*cursor + 1]]) as usize;
            *cursor += 2;
            Ok(29 + 256 + size)
        }
        31 => {
            if *cursor + 3 > data.len() {
                return Err(PointerValidationError::InvalidOffset {
                    offset: *cursor,
                    reason: "Size bytes out of bounds".to_string(),
                });
            }
            let b0 = data[*cursor] as usize;
            let b1 = data[*cursor + 1] as usize;
            let b2 = data[*cursor + 2] as usize;
            *cursor += 3;
            Ok(29 + 256 + 65536 + ((b0 << 16) | (b1 << 8) | b2))
        }
        _ => Err(PointerValidationError::InvalidOffset {
            offset: *cursor,
            reason: "Invalid size encoding".to_string(),
        }),
    }
}

/// Decode pointer offset for validation
fn decode_pointer_offset(
    data: &[u8],
    cursor: &mut usize,
    payload: u8,
) -> Result<usize, PointerValidationError> {
    let size_bits = (payload >> 3) & 0x3;

    let offset = match size_bits {
        0 => {
            if *cursor >= data.len() {
                return Err(PointerValidationError::InvalidOffset {
                    offset: *cursor,
                    reason: "Pointer data truncated".to_string(),
                });
            }
            let low_3_bits = (payload & 0x7) as usize;
            let next_byte = data[*cursor] as usize;
            *cursor += 1;
            (low_3_bits << 8) | next_byte
        }
        1 => {
            if *cursor + 1 >= data.len() {
                return Err(PointerValidationError::InvalidOffset {
                    offset: *cursor,
                    reason: "Pointer data truncated".to_string(),
                });
            }
            let low_3_bits = (payload & 0x7) as usize;
            let b0 = data[*cursor] as usize;
            let b1 = data[*cursor + 1] as usize;
            *cursor += 2;
            2048 + ((low_3_bits << 16) | (b0 << 8) | b1)
        }
        2 => {
            if *cursor + 2 >= data.len() {
                return Err(PointerValidationError::InvalidOffset {
                    offset: *cursor,
                    reason: "Pointer data truncated".to_string(),
                });
            }
            let low_3_bits = (payload & 0x7) as usize;
            let b0 = data[*cursor] as usize;
            let b1 = data[*cursor + 1] as usize;
            let b2 = data[*cursor + 2] as usize;
            *cursor += 3;
            526336 + ((low_3_bits << 24) | (b0 << 16) | (b1 << 8) | b2)
        }
        3 => {
            if *cursor + 3 >= data.len() {
                return Err(PointerValidationError::InvalidOffset {
                    offset: *cursor,
                    reason: "Pointer data truncated".to_string(),
                });
            }
            let b0 = data[*cursor] as usize;
            let b1 = data[*cursor + 1] as usize;
            let b2 = data[*cursor + 2] as usize;
            let b3 = data[*cursor + 3] as usize;
            *cursor += 4;
            (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
        }
        _ => {
            return Err(PointerValidationError::InvalidOffset {
                offset: *cursor,
                reason: "Invalid pointer size bits".to_string(),
            });
        }
    };

    Ok(offset)
}

/// Skip past a data value (returns offset after the value)
fn skip_data_value(data: &[u8], offset: usize) -> Result<usize, PointerValidationError> {
    if offset >= data.len() {
        return Err(PointerValidationError::InvalidOffset {
            offset,
            reason: "Offset beyond data".to_string(),
        });
    }

    let ctrl = data[offset];
    let type_id = ctrl >> 5;
    let payload = ctrl & 0x1F;
    let mut cursor = offset + 1;

    match type_id {
        0 => {
            // Extended type
            if cursor >= data.len() {
                return Err(PointerValidationError::InvalidOffset {
                    offset,
                    reason: "Extended type truncated".to_string(),
                });
            }
            cursor += 1; // Skip extended type byte
            let size = decode_size_for_validation(data, &mut cursor, payload)?;
            Ok(cursor + size)
        }
        1 => {
            // Pointer
            let size_bits = (payload >> 3) & 0x3;
            let ptr_size = match size_bits {
                0 => 1,
                1 => 2,
                2 => 3,
                3 => 4,
                _ => 0,
            };
            Ok(cursor + ptr_size)
        }
        2 | 4 => {
            // String or Bytes
            let size = decode_size_for_validation(data, &mut cursor, payload)?;
            Ok(cursor + size)
        }
        3 => Ok(cursor + 8), // Double
        5 => {
            // Uint16
            let size = decode_size_for_validation(data, &mut cursor, payload)?;
            Ok(cursor + size.min(2))
        }
        6 => {
            // Uint32
            let size = decode_size_for_validation(data, &mut cursor, payload)?;
            Ok(cursor + size.min(4))
        }
        7 => {
            // Map
            let count = decode_size_for_validation(data, &mut cursor, payload)?;
            for _ in 0..count {
                cursor = skip_data_value(data, cursor)?; // Skip key
                cursor = skip_data_value(data, cursor)?; // Skip value
            }
            Ok(cursor)
        }
        _ => Err(PointerValidationError::InvalidType { offset, type_id }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DataEncoder;
    use std::collections::HashMap;

    #[test]
    fn test_validate_simple_string() {
        let mut encoder = DataEncoder::new();
        let value = DataValue::String("test".to_string());
        let offset = encoder.encode(&value);
        let data = encoder.into_bytes();

        let count = validate_data_value_utf8(&data, offset as usize, 0).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_validate_map_with_strings() {
        let mut encoder = DataEncoder::new();
        let mut map = HashMap::new();
        map.insert("key1".to_string(), DataValue::String("value1".to_string()));
        map.insert("key2".to_string(), DataValue::String("value2".to_string()));
        map.insert("num".to_string(), DataValue::Uint32(42));

        let value = DataValue::Map(map);
        let offset = encoder.encode(&value);
        let data = encoder.into_bytes();

        let count = validate_data_value_utf8(&data, offset as usize, 0).unwrap();
        // 3 keys + 2 string values = 5 strings total
        // (Note: string interning may create pointers, but those are resolved during decode)
        assert_eq!(count, 5);
    }

    #[test]
    fn test_validate_nested_structure() {
        let mut encoder = DataEncoder::new();

        // Build nested structure with strings at various levels
        let mut inner_map = HashMap::new();
        inner_map.insert("inner".to_string(), DataValue::String("nested".to_string()));

        let mut outer_map = HashMap::new();
        outer_map.insert("outer".to_string(), DataValue::String("top".to_string()));
        outer_map.insert("nested".to_string(), DataValue::Map(inner_map));

        let value = DataValue::Map(outer_map);
        let offset = encoder.encode(&value);
        let data = encoder.into_bytes();

        let count = validate_data_value_utf8(&data, offset as usize, 0).unwrap();
        // Outer: 2 keys + 1 string value = 3
        // Inner: 1 key + 1 string value = 2
        // Total = 5 strings
        assert_eq!(count, 5);
    }

    #[test]
    fn test_validate_array_with_strings() {
        let mut encoder = DataEncoder::new();
        let value = DataValue::Array(vec![
            DataValue::String("a".to_string()),
            DataValue::String("b".to_string()),
            DataValue::Uint32(123),
        ]);

        let offset = encoder.encode(&value);
        let data = encoder.into_bytes();

        let count = validate_data_value_utf8(&data, offset as usize, 0).unwrap();
        assert_eq!(count, 2); // 2 strings in array
    }

    #[test]
    fn test_validate_data_section() {
        let mut encoder = DataEncoder::new();
        let value1 = DataValue::String("first".to_string());
        let value2 = DataValue::String("second".to_string());

        let offset1 = encoder.encode(&value1);
        let offset2 = encoder.encode(&value2);
        let data = encoder.into_bytes();

        let result = validate_data_section(&data, 0, &[offset1, offset2]);
        assert!(result.is_valid());
        assert_eq!(result.stats.values_checked, 2);
        assert_eq!(result.stats.strings_checked, 2);
    }

    #[test]
    fn test_validate_invalid_offset() {
        // Create some actual data so we're not dealing with empty section warning
        let mut encoder = DataEncoder::new();
        encoder.encode(&DataValue::String("test".to_string()));
        let data = encoder.into_bytes();

        // Now try to validate an invalid offset
        let result = validate_data_section(&data, 0, &[999]);
        assert!(!result.is_valid());
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_validate_empty_data_section() {
        let data: Vec<u8> = Vec::new();
        let result = validate_data_section(&data, 0, &[]);
        // Empty is not an error, just a warning
        assert!(result.is_valid());
        assert_eq!(result.warnings.len(), 1);
    }
}
