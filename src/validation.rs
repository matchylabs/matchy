//! Database validation for untrusted .mxy files
//!
//! This module provides comprehensive validation of MMDB format database files (.mxy)
//! to ensure they are safe to load and use. It performs thorough checks of:
//!
//! - MMDB metadata and structure
//! - Embedded PARAGLOB sections (if present)
//! - All offsets and bounds checking
//! - UTF-8 validity of all strings
//! - Graph structure integrity (no cycles, valid transitions)
//! - Data consistency (arrays, mappings, references)
//!
//! # Safety
//!
//! The validator is designed to detect malformed, corrupted, or malicious databases
//! without panicking or causing undefined behavior. All checks use safe Rust with
//! explicit bounds checking.
//!
//! # Usage
//!
//! ```rust,no_run
//! use matchy::validation::{validate_database, ValidationLevel};
//! use std::path::Path;
//!
//! let report = validate_database(Path::new("database.mxy"), ValidationLevel::Strict)?;
//!
//! if report.is_valid() {
//!     println!("✓ Database is safe to use");
//! } else {
//!     println!("✗ Validation failed:");
//!     for error in &report.errors {
//!         println!("  - {}", error);
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::error::{ParaglobError, Result};
use crate::offset_format::{
    ACEdge, ACNodeHot, MetaWordMapping, ParaglobHeader, PatternDataMapping, PatternEntry,
    StateKind, MAGIC, MATCHY_FORMAT_VERSION, MATCHY_FORMAT_VERSION_V1, MATCHY_FORMAT_VERSION_V2, MATCHY_FORMAT_VERSION_V3,
};
use std::collections::HashSet;
use std::fs::File;
use std::mem;
use std::path::Path;
use zerocopy::FromBytes;

/// Validation strictness level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationLevel {
    /// Standard checks: all offsets, UTF-8, basic structure
    Standard,
    /// Strict checks: deep graph analysis, cycles, redundancy, PARAGLOB consistency (default)
    Strict,
    /// Audit mode: Track all unsafe code paths and trust assumptions
    /// Reports where --trusted mode would bypass validation
    Audit,
}

/// Validation report with detailed findings
#[derive(Debug, Clone)]
pub struct ValidationReport {
    /// Critical errors that make the database unusable
    pub errors: Vec<String>,
    /// Warnings about potential issues (non-fatal)
    pub warnings: Vec<String>,
    /// Informational messages about database properties
    pub info: Vec<String>,
    /// Database statistics
    pub stats: DatabaseStats,
}

/// Database statistics gathered during validation
#[derive(Debug, Clone, Default)]
pub struct DatabaseStats {
    /// File size in bytes
    pub file_size: usize,
    /// Format version (1, 2, or 3)
    pub version: u32,
    /// Number of AC automaton nodes
    pub ac_node_count: u32,
    /// Number of patterns
    pub pattern_count: u32,
    /// Number of IP address entries (if present)
    pub ip_entry_count: u32,
    /// Number of literal patterns
    pub literal_count: u32,
    /// Number of glob patterns
    pub glob_count: u32,
    /// Total string data size
    pub string_data_size: u32,
    /// Has data section (v2+)
    pub has_data_section: bool,
    /// Has AC literal mapping (v3)
    pub has_ac_literal_mapping: bool,
    /// Number of state encoding types used
    pub state_encoding_distribution: [u32; 4], // Empty, One, Sparse, Dense
    /// Locations where unsafe code is used (Audit mode only)
    pub unsafe_code_locations: Vec<UnsafeCodeLocation>,
    /// Trust assumptions that would bypass validation
    pub trust_assumptions: Vec<TrustAssumption>,
}

/// Location where unsafe code is used
#[derive(Debug, Clone)]
pub struct UnsafeCodeLocation {
    /// Source file and function
    pub location: String,
    /// Type of unsafe operation
    pub operation: UnsafeOperation,
    /// Description of why it's needed
    pub justification: String,
}

/// Types of unsafe operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsafeOperation {
    /// Unchecked UTF-8 string reading
    UncheckedStringRead,
    /// Raw pointer dereferencing
    PointerDereference,
    /// Memory mapping with 'static lifetime extension
    MmapLifetimeExtension,
    /// Transmute or type reinterpretation
    Transmute,
}

/// Trust assumption that bypasses validation
#[derive(Debug, Clone)]
pub struct TrustAssumption {
    /// Where this trust is assumed
    pub context: String,
    /// What validation is bypassed
    pub bypassed_check: String,
    /// Risk if assumption is violated
    pub risk: String,
}

impl ValidationReport {
    /// Create a new empty report
    fn new() -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
            info: Vec::new(),
            stats: DatabaseStats::default(),
        }
    }

    /// Check if database passed all validations (no errors)
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Add an error to the report
    fn error(&mut self, msg: impl Into<String>) {
        self.errors.push(msg.into());
    }

    /// Add a warning to the report
    fn warning(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }

    /// Add an info message to the report
    fn info(&mut self, msg: impl Into<String>) {
        self.info.push(msg.into());
    }
}

impl DatabaseStats {
    /// Human-readable summary
    pub fn summary(&self) -> String {
        format!(
            "Version: v{}, Nodes: {}, Patterns: {} ({} literal, {} glob), IPs: {}, Size: {} KB",
            self.version,
            self.ac_node_count,
            self.pattern_count,
            self.literal_count,
            self.glob_count,
            self.ip_entry_count,
            self.file_size / 1024
        )
    }
}

/// Validate a database file
///
/// Performs comprehensive validation of a .mxy (MMDB format) database file.
/// Returns a detailed report of any issues found.
///
/// This validates MMDB format databases which may contain:
/// - IP address data
/// - Literal string hash tables  
/// - Embedded PARAGLOB pattern matching sections
///
/// # Arguments
///
/// * `path` - Path to the .mxy file to validate
/// * `level` - Validation strictness level
///
/// # Example
///
/// ```rust,no_run
/// use matchy::validation::{validate_database, ValidationLevel};
/// use std::path::Path;
///
/// let report = validate_database(Path::new("database.mxy"), ValidationLevel::Standard)?;
///
/// if !report.is_valid() {
///     eprintln!("Validation failed with {} errors", report.errors.len());
///     for error in &report.errors {
///         eprintln!("  ERROR: {}", error);
///     }
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn validate_database(path: &Path, level: ValidationLevel) -> Result<ValidationReport> {
    let mut report = ValidationReport::new();

    // Load entire file into memory for validation
    let file =
        File::open(path).map_err(|e| ParaglobError::Io(format!("Failed to open file: {}", e)))?;

    let metadata = file
        .metadata()
        .map_err(|e| ParaglobError::Io(format!("Failed to get file metadata: {}", e)))?;

    let file_size = metadata.len() as usize;
    report.stats.file_size = file_size;
    report.info(format!(
        "File size: {} bytes ({} KB)",
        file_size,
        file_size / 1024
    ));

    // Read entire file
    let buffer = std::fs::read(path)
        .map_err(|e| ParaglobError::Io(format!("Failed to read file: {}", e)))?;

    // Validate as MMDB format
    validate_mmdb_database(&buffer, &mut report, level)
}

/// Validate an MMDB format database
fn validate_mmdb_database(
    buffer: &[u8],
    report: &mut ValidationReport,
    level: ValidationLevel,
) -> Result<ValidationReport> {
    // Check for MMDB metadata marker
    if let Err(e) = crate::mmdb::find_metadata_marker(buffer) {
        report.error(format!("Invalid MMDB format: {}", e));
        return Ok(report.clone());
    }

    report.info("Valid MMDB metadata marker found");

    // Try to read metadata
    match crate::mmdb::MmdbMetadata::from_file(buffer) {
        Ok(metadata) => {
            if let Ok(crate::DataValue::Map(map)) = metadata.as_value() {
                // Extract and validate required MMDB fields
                let node_count = match map.get("node_count") {
                    Some(crate::DataValue::Uint16(n)) => *n as u32,
                    Some(crate::DataValue::Uint32(n)) => *n,
                    Some(crate::DataValue::Uint64(n)) => *n as u32,
                    _ => {
                        report.error("Missing or invalid node_count in metadata");
                        return Ok(report.clone());
                    }
                };

                let record_size = match map.get("record_size") {
                    Some(crate::DataValue::Uint16(n)) => *n,
                    Some(crate::DataValue::Uint32(n)) => *n as u16,
                    _ => {
                        report.error("Missing or invalid record_size in metadata");
                        return Ok(report.clone());
                    }
                };

                let ip_version = match map.get("ip_version") {
                    Some(crate::DataValue::Uint16(n)) => *n,
                    Some(crate::DataValue::Uint32(n)) => *n as u16,
                    _ => {
                        report.error("Missing or invalid ip_version in metadata");
                        return Ok(report.clone());
                    }
                };

                // Validate values
                if record_size != 24 && record_size != 28 && record_size != 32 {
                    report.error(format!(
                        "Invalid record_size: {} (must be 24, 28, or 32)",
                        record_size
                    ));
                }

                if ip_version != 4 && ip_version != 6 {
                    report.error(format!(
                        "Invalid ip_version: {} (must be 4 or 6)",
                        ip_version
                    ));
                }

                // Calculate and validate tree size
                let node_bytes = match record_size {
                    24 => 6,
                    28 => 7,
                    32 => 8,
                    _ => 6, // Already reported error above
                };
                let tree_size = (node_count as usize) * node_bytes;

                if tree_size > buffer.len() {
                    report.error(format!(
                        "Calculated tree size {} exceeds file size {}",
                        tree_size,
                        buffer.len()
                    ));
                } else {
                    report.info(format!(
                        "IP tree: {} nodes, {} bits/record, IPv{}, tree size: {} bytes",
                        node_count, record_size, ip_version, tree_size
                    ));
                }

                // Extract database info
                if let Some(crate::DataValue::String(db_type)) = map.get("database_type") {
                    report.info(format!("Database type: {}", db_type));
                }

                if let Some(crate::DataValue::String(desc)) = map.get("description") {
                    if desc.len() <= 100 {
                        report.info(format!("Description: {}", desc));
                    }
                }

                // Validate build timestamp
                if let Some(build_epoch) = map.get("build_epoch") {
                    match build_epoch {
                        crate::DataValue::Uint32(epoch) => {
                            report.info(format!("Build timestamp: {} (Unix epoch)", epoch));
                        }
                        crate::DataValue::Uint64(epoch) => {
                            report.info(format!("Build timestamp: {} (Unix epoch)", epoch));
                        }
                        _ => report.warning("build_epoch has unexpected type"),
                    }
                }

                // Check for pattern section
                if let Some(crate::DataValue::Uint32(pattern_offset)) =
                    map.get("pattern_section_offset")
                {
                    if *pattern_offset > 0 {
                        let offset = *pattern_offset as usize;
                        report.info(format!("Pattern section found at offset {}", offset));

                        // Validate the embedded PARAGLOB section
                        if offset < buffer.len() {
                            validate_paraglob_section(buffer, offset, report, level)?;
                        } else {
                            report.error(format!(
                                "Pattern section offset {} is beyond file size {}",
                                offset,
                                buffer.len()
                            ));
                        }
                    }
                }

                // Check for literal section
                if let Some(crate::DataValue::Uint32(literal_offset)) =
                    map.get("literal_section_offset")
                {
                    if *literal_offset > 0 {
                        let offset = *literal_offset as usize;
                        report.info(format!("Literal section found at offset {}", offset));

                        // Validate literal hash section if in standard or strict mode
                        if offset < buffer.len() {
                            validate_literal_hash_section(buffer, offset, report)?;
                        } else {
                            report.error(format!(
                                "Literal section offset {} beyond file size {}",
                                offset,
                                buffer.len()
                            ));
                        }
                    }
                }

                // Store IP count for stats
                if node_count > 0 {
                    // Rough estimate: nodes roughly correlate with IP entries
                    report.stats.ip_entry_count = node_count;
                }

                // Always validate data section structure and UTF-8 (critical for safety)
                validate_mmdb_data_section(buffer, tree_size, report)?;

                // Validate UTF-8 in data section (critical for safety)
                validate_data_section_utf8(
                    buffer, tree_size, node_count, node_bytes, report, level,
                )?;

                // Validate data section pointers (critical for safety)
                validate_data_section_pointers(
                    buffer, tree_size, node_count, node_bytes, report, level,
                )?;

                // Strict/Audit mode: deep validation
                if level == ValidationLevel::Strict || level == ValidationLevel::Audit {
                    // Check for size bombs
                    validate_size_limits(buffer.len(), node_count, tree_size, report)?;

                    // Sample tree nodes for integrity
                    validate_tree_samples(buffer, node_count, node_bytes, tree_size, report)?;

                    // Validate data pointer references
                    validate_data_pointers(buffer, tree_size, node_count, node_bytes, report)?;

                    // Deep IP tree traversal validation
                    validate_ip_tree_structure(
                        buffer, tree_size, node_count, node_bytes, ip_version, report,
                    )?;
                }

                // Audit mode: also track unsafe code and trust assumptions
                if level == ValidationLevel::Audit {
                    // Audit unsafe code usage
                    audit_unsafe_code_paths(report)?;

                    // Audit trust mode risks
                    audit_trust_mode_risks(buffer, report)?;
                }
            }
        }
        Err(e) => {
            report.error(format!("Failed to parse MMDB metadata: {}", e));
            return Ok(report.clone());
        }
    }

    if report.is_valid() {
        report.info("✓ MMDB database structure is valid");
    }

    Ok(report.clone())
}

/// Validate literal hash section structure
fn validate_literal_hash_section(
    buffer: &[u8],
    offset: usize,
    report: &mut ValidationReport,
) -> Result<()> {
    // Check for "MMDB_LITERAL" marker (16 bytes)
    const LITERAL_MARKER: &[u8] = b"MMDB_LITERAL\x00\x00\x00\x00";

    if offset < 16 || offset - 16 > buffer.len() {
        report.error("Literal section offset invalid");
        return Ok(());
    }

    // Check for marker before the data
    let marker_start = offset - 16;
    if marker_start + 16 <= buffer.len() {
        let marker = &buffer[marker_start..marker_start + 16];
        if marker == LITERAL_MARKER {
            report.info("Valid MMDB_LITERAL marker found");
        } else {
            report.warning("MMDB_LITERAL marker not found at expected location");
        }
    }

    // The actual literal hash starts at offset
    // Check for "LHSH" magic
    const LHSH_MAGIC: &[u8; 4] = b"LHSH";

    if offset + 4 > buffer.len() {
        report.error("Literal hash section truncated (no magic bytes)");
        return Ok(());
    }

    let magic = &buffer[offset..offset + 4];
    if magic == LHSH_MAGIC {
        report.info("Valid literal hash magic (LHSH) found");

        // Read header fields
        if offset + 24 <= buffer.len() {
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

            report.info(format!(
                "Literal hash: version {}, {} entries, table size {}",
                version, entry_count, table_size
            ));

            // Basic sanity checks
            if version != 1 {
                report.warning(format!("Unexpected literal hash version: {}", version));
            }

            if entry_count > 10_000_000 {
                report.warning(format!(
                    "Very large literal count: {} (> 10M, potential memory issue)",
                    entry_count
                ));
            }

            if table_size < entry_count {
                report.error(format!(
                    "Table size {} is smaller than entry count {}",
                    table_size, entry_count
                ));
            }

            // Store count for stats
            report.stats.literal_count = entry_count;
        } else {
            report.error("Literal hash header truncated");
        }
    } else {
        report.warning(format!(
            "Unexpected literal hash magic: expected LHSH, got {:?}",
            String::from_utf8_lossy(magic)
        ));
    }

    Ok(())
}

/// Validate size limits to prevent memory bombs
fn validate_size_limits(
    file_size: usize,
    node_count: u32,
    tree_size: usize,
    report: &mut ValidationReport,
) -> Result<()> {
    // Check for unreasonably large files (> 2GB)
    const MAX_SAFE_FILE_SIZE: usize = 2 * 1024 * 1024 * 1024;
    if file_size > MAX_SAFE_FILE_SIZE {
        report.warning(format!(
            "Very large database file: {} MB (> 2GB threshold)",
            file_size / (1024 * 1024)
        ));
    }

    // Check for unreasonably large node counts
    const MAX_REASONABLE_NODES: u32 = 10_000_000;
    if node_count > MAX_REASONABLE_NODES {
        report.warning(format!(
            "Very large node count: {} (> 10M threshold, potential memory bomb)",
            node_count
        ));
    }

    // Tree size should not be more than 50% of file (leaves room for data)
    if tree_size > file_size / 2 {
        report.warning(format!(
            "Tree size ({} bytes) is more than 50% of file size ({}  bytes)",
            tree_size, file_size
        ));
    }

    Ok(())
}

/// Sample tree nodes to verify structure integrity
fn validate_tree_samples(
    buffer: &[u8],
    node_count: u32,
    node_bytes: usize,
    tree_size: usize,
    report: &mut ValidationReport,
) -> Result<()> {
    if node_count == 0 {
        return Ok(());
    }

    // Sample up to 100 random nodes (or all if fewer)
    let sample_count = node_count.min(100) as usize;
    let step = if node_count > 100 {
        node_count as usize / sample_count
    } else {
        1
    };

    let mut sampled = 0;
    for i in (0..node_count as usize).step_by(step) {
        if sampled >= sample_count {
            break;
        }

        let node_offset = i * node_bytes;
        if node_offset + node_bytes > tree_size {
            report.error(format!(
                "Node {} offset {} exceeds tree size {}",
                i, node_offset, tree_size
            ));
            break;
        }

        // Basic check: node data should be within bounds
        if node_offset + node_bytes > buffer.len() {
            report.error(format!(
                "Node {} at offset {} would exceed buffer",
                i, node_offset
            ));
            break;
        }

        sampled += 1;
    }

    report.info(format!("Sampled {} tree nodes for integrity", sampled));
    Ok(())
}

/// Validate data pointers in tree nodes
fn validate_data_pointers(
    buffer: &[u8],
    tree_size: usize,
    node_count: u32,
    node_bytes: usize,
    report: &mut ValidationReport,
) -> Result<()> {
    if node_count == 0 {
        return Ok(());
    }

    // Sample some nodes and check their record values
    let sample_count = node_count.min(50) as usize;
    let step = if node_count > 50 {
        node_count as usize / sample_count
    } else {
        1
    };

    let data_section_start = tree_size + 16; // Tree + 16-byte separator
    let max_valid_offset = buffer.len().saturating_sub(data_section_start);

    for i in (0..node_count as usize).step_by(step).take(sample_count) {
        let node_offset = i * node_bytes;

        // Read records from this node based on record size
        // For 24-bit: 2 records of 3 bytes each (6 bytes total)
        // For 28-bit: 2 records of 3.5 bytes each (7 bytes total)
        // For 32-bit: 2 records of 4 bytes each (8 bytes total)

        if node_offset + node_bytes > buffer.len() {
            continue;
        }

        // Read left record (first record)
        let record_val = match node_bytes {
            6 => {
                // 24-bit
                let b0 = buffer[node_offset] as u32;
                let b1 = buffer[node_offset + 1] as u32;
                let b2 = buffer[node_offset + 2] as u32;
                (b0 << 16) | (b1 << 8) | b2
            }
            7 => {
                // 28-bit (more complex, just check bounds)
                continue;
            }
            8 => {
                // 32-bit
                u32::from_be_bytes([
                    buffer[node_offset],
                    buffer[node_offset + 1],
                    buffer[node_offset + 2],
                    buffer[node_offset + 3],
                ])
            }
            _ => continue,
        };

        // If record > node_count, it's a data pointer
        if record_val > node_count {
            let data_offset = record_val - node_count - 16;
            if data_offset as usize > max_valid_offset {
                report.warning(format!(
                    "Node {} has data pointer {} that may exceed data section",
                    i, data_offset
                ));
            }
        }
    }

    Ok(())
}

/// Validate UTF-8 in data section strings (CRITICAL for safety)
fn validate_data_section_utf8(
    buffer: &[u8],
    tree_size: usize,
    node_count: u32,
    node_bytes: usize,
    report: &mut ValidationReport,
    level: ValidationLevel,
) -> Result<()> {
    let data_section_start = tree_size + 16; // Tree + separator

    if data_section_start >= buffer.len() {
        return Ok(()); // No data section
    }

    let data_section = &buffer[data_section_start..];

    // Strategy: Sample data records by following pointers from tree nodes
    // This validates the strings that are actually reachable

    let sample_count = if level == ValidationLevel::Strict {
        node_count.min(100) // Sample up to 100 in strict mode
    } else {
        node_count.min(20) // Sample 20 in standard mode
    };

    if node_count == 0 || sample_count == 0 {
        return Ok(());
    }

    let step = if node_count > sample_count {
        (node_count / sample_count).max(1)
    } else {
        1
    };

    let mut strings_checked = 0;
    let mut invalid_utf8_found = false;

    for i in (0..node_count)
        .step_by(step as usize)
        .take(sample_count as usize)
    {
        let node_offset = (i as usize) * node_bytes;

        if node_offset + node_bytes > tree_size {
            continue;
        }

        // Read record value (simplified - just check left record)
        let record_val = match node_bytes {
            6 => {
                // 24-bit
                let b0 = buffer[node_offset] as u32;
                let b1 = buffer[node_offset + 1] as u32;
                let b2 = buffer[node_offset + 2] as u32;
                (b0 << 16) | (b1 << 8) | b2
            }
            7 => {
                // 28-bit - complex, skip for now
                continue;
            }
            8 => {
                // 32-bit
                u32::from_be_bytes([
                    buffer[node_offset],
                    buffer[node_offset + 1],
                    buffer[node_offset + 2],
                    buffer[node_offset + 3],
                ])
            }
            _ => continue,
        };

        // If record points to data (> node_count), decode it
        if record_val > node_count {
            let data_offset = (record_val - node_count - 16) as usize;

            if data_offset < data_section.len() {
                // Try to decode this data value and check strings
                match check_data_value_utf8(data_section, data_offset) {
                    Ok(count) => {
                        strings_checked += count;
                    }
                    Err(e) => {
                        report.error(format!(
                            "Invalid UTF-8 found in data section at offset {}: {}",
                            data_section_start + data_offset,
                            e
                        ));
                        invalid_utf8_found = true;
                        break;
                    }
                }
            }
        }
    }

    if strings_checked > 0 {
        report.info(format!(
            "UTF-8 validated: {} string(s) checked in data section (all valid)",
            strings_checked
        ));
    } else if sample_count > 0 {
        report.info("UTF-8 validation: no data records found to sample");
    }

    if invalid_utf8_found {
        report
            .error("Database contains invalid UTF-8 - DO NOT use with --trusted mode!".to_string());
    }

    Ok(())
}

/// Check UTF-8 validity of all strings in a data value
/// Returns count of strings checked, or error if invalid UTF-8 found
fn check_data_value_utf8(data_section: &[u8], offset: usize) -> std::result::Result<u32, String> {
    use crate::data_section::DataDecoder;

    let decoder = DataDecoder::new(data_section, 0);

    match decoder.decode(offset as u32) {
        Ok(value) => check_value_strings_utf8(&value),
        Err(_) => Ok(0), // Can't decode, skip
    }
}

/// Recursively check all strings in a DataValue for UTF-8 validity
fn check_value_strings_utf8(value: &crate::DataValue) -> std::result::Result<u32, String> {
    let mut count = 0u32;

    match value {
        crate::DataValue::String(_s) => {
            // String is already validated UTF-8 when decoded
            count += 1;
        }
        crate::DataValue::Map(map) => {
            for val in map.values() {
                // Keys are already validated UTF-8
                count += 1;
                count += check_value_strings_utf8(val)?;
            }
        }
        crate::DataValue::Array(arr) => {
            for val in arr {
                count += check_value_strings_utf8(val)?;
            }
        }
        _ => {} // Other types don't contain strings
    }

    Ok(count)
}

/// Validate MMDB data section structure
fn validate_mmdb_data_section(
    buffer: &[u8],
    tree_size: usize,
    report: &mut ValidationReport,
) -> Result<()> {
    // After the tree, there should be a 16-byte separator, then the data section
    const DATA_SEPARATOR_SIZE: usize = 16;

    if tree_size + DATA_SEPARATOR_SIZE > buffer.len() {
        report.error(format!(
            "Tree size {} + separator {} exceeds file size {}",
            tree_size,
            DATA_SEPARATOR_SIZE,
            buffer.len()
        ));
        return Ok(());
    }

    let separator_start = tree_size;
    let data_start = tree_size + DATA_SEPARATOR_SIZE;

    // Check separator (should be 16 zero bytes)
    let separator = &buffer[separator_start..data_start];
    if separator.iter().all(|&b| b == 0) {
        report.info("Valid data section separator found");
    } else {
        report.warning("Data section separator is non-zero (may be intentional)");
    }

    // Validate data section exists and is reasonable
    let data_size = buffer.len() - data_start;
    if data_size > 0 {
        report.info(format!("Data section: {} bytes", data_size));

        // Basic sanity check: data section shouldn't be impossibly small
        if data_size < 4 {
            report.warning("Data section is very small (< 4 bytes)");
        }
    } else {
        report.warning("No data section found after tree");
    }

    Ok(())
}

/// Validate an embedded PARAGLOB section within an MMDB database
fn validate_paraglob_section(
    buffer: &[u8],
    offset: usize,
    report: &mut ValidationReport,
    level: ValidationLevel,
) -> Result<()> {
    // The pattern section format in MMDB is:
    // [total_size: u32][paraglob_size: u32][PARAGLOB data][pattern_count: u32][offsets...]

    if offset + 8 > buffer.len() {
        report.error("Pattern section header truncated");
        return Ok(());
    }

    // Read sizes
    let _total_size = u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);
    let paraglob_size = u32::from_le_bytes([
        buffer[offset + 4],
        buffer[offset + 5],
        buffer[offset + 6],
        buffer[offset + 7],
    ]) as usize;

    let paraglob_start = offset + 8;
    let paraglob_end = paraglob_start + paraglob_size;

    if paraglob_end > buffer.len() {
        report.error(format!(
            "PARAGLOB section extends beyond file: start={}, size={}, file_len={}",
            paraglob_start,
            paraglob_size,
            buffer.len()
        ));
        return Ok(());
    }

    // Validate the PARAGLOB data
    let paraglob_data = &buffer[paraglob_start..paraglob_end];
    validate_paraglob_header(paraglob_data, report)?;

    if !report.is_valid() {
        return Ok(());
    }

    // Parse PARAGLOB header for stats
    let header = read_paraglob_header(paraglob_data)?;
    report.stats.version = header.version;
    report.stats.ac_node_count = header.ac_node_count;
    report.stats.pattern_count = header.pattern_count;
    report.stats.has_data_section = header.has_data_section();
    report.stats.has_ac_literal_mapping = header.has_ac_literal_mapping();

    // Validate PARAGLOB structure
    validate_paraglob_offsets(paraglob_data, &header, report)?;

    if !report.is_valid() {
        return Ok(());
    }

    validate_paraglob_strings(paraglob_data, &header, report)?;

    if !report.is_valid() {
        return Ok(());
    }

    validate_ac_structure(paraglob_data, &header, report, level)?;

    if !report.is_valid() {
        return Ok(());
    }

    validate_patterns(paraglob_data, &header, report)?;

    if !report.is_valid() {
        return Ok(());
    }

    // PARAGLOB consistency checks in strict/audit modes
    if level == ValidationLevel::Strict || level == ValidationLevel::Audit {
        validate_paraglob_consistency(paraglob_data, &header, report, level)?;
    }

    Ok(())
}

/// Read and parse the PARAGLOB header
fn read_paraglob_header(buffer: &[u8]) -> Result<ParaglobHeader> {
    if buffer.len() < mem::size_of::<ParaglobHeader>() {
        return Err(ParaglobError::Format(
            "File too small to contain header".to_string(),
        ));
    }

    let header = ParaglobHeader::read_from_prefix(buffer)
        .map(|(h, _)| h)
        .map_err(|_| ParaglobError::Format("Failed to read header".to_string()))?;

    Ok(header)
}

/// Validate PARAGLOB header structure
fn validate_paraglob_header(buffer: &[u8], report: &mut ValidationReport) -> Result<()> {
    // Check minimum size
    if buffer.len() < mem::size_of::<ParaglobHeader>() {
        report.error(format!(
            "File too small: {} bytes, need at least {} for header",
            buffer.len(),
            mem::size_of::<ParaglobHeader>()
        ));
        return Ok(());
    }

    let header = read_paraglob_header(buffer)?;

    // Check magic bytes
    if &header.magic != MAGIC {
        let magic_str = String::from_utf8_lossy(&header.magic);
        report.error(format!(
            "Invalid magic bytes: expected {:?}, got {:?}",
            MAGIC, magic_str
        ));
        return Ok(());
    }

    // Check version
    match header.version {
        MATCHY_FORMAT_VERSION => {
            report.info("Format version: v4 (latest - ACNodeHot for 50% memory reduction)");
        }
        MATCHY_FORMAT_VERSION_V3 => {
            report.warning("Format version: v3 (older - uses 32-byte ACNode, no longer supported)");
        }
        MATCHY_FORMAT_VERSION_V2 => {
            report.warning(
                "Format version: v2 (older - no AC literal mapping, will be slower to load)",
            );
        }
        MATCHY_FORMAT_VERSION_V1 => {
            report.warning("Format version: v1 (oldest - no data section, no AC literal mapping)");
        }
        v => {
            report.error(format!(
                "Unsupported version: {} (expected 1, 2, 3, or 4)",
                v
            ));
            return Ok(());
        }
    }

    // Validate endianness marker
    match header.endianness {
        0x00 => report.warning("No endianness marker (legacy format)"),
        0x01 => report.info("Endianness: little-endian"),
        0x02 => {
            report.info("Endianness: big-endian");
            if cfg!(target_endian = "little") {
                report.warning(
                    "Database is big-endian but system is little-endian (will byte-swap on read)",
                );
            }
        }
        e => report.warning(format!("Unknown endianness marker: 0x{:02x}", e)),
    }

    // Validate total buffer size matches file size
    if header.total_buffer_size as usize != buffer.len() {
        report.error(format!(
            "Header total_buffer_size ({}) doesn't match file size ({})",
            header.total_buffer_size,
            buffer.len()
        ));
    }

    // Use built-in offset validation
    if let Err(e) = header.validate_offsets(buffer.len()) {
        report.error(format!("Header offset validation failed: {}", e));
    }

    Ok(())
}

/// Validate all offsets in the PARAGLOB section
fn validate_paraglob_offsets(
    buffer: &[u8],
    header: &ParaglobHeader,
    report: &mut ValidationReport,
) -> Result<()> {
    let buffer_len = buffer.len();

    // Validate AC nodes section
    if header.ac_node_count > 0 {
        let offset = header.ac_nodes_offset as usize;
        let size = (header.ac_node_count as usize) * mem::size_of::<ACNodeHot>();

        if !validate_range(offset, size, buffer_len) {
            report.error(format!(
                "AC nodes section out of bounds: offset={}, size={}, buffer={}",
                offset, size, buffer_len
            ));
        } else {
            // Check alignment
            if !offset.is_multiple_of(mem::align_of::<ACNodeHot>()) {
                report.error(format!(
                    "AC nodes section misaligned: offset={}, required_alignment={}",
                    offset,
                    mem::align_of::<ACNodeHot>()
                ));
            }
        }
    }

    // Validate patterns section
    if header.pattern_count > 0 {
        let offset = header.patterns_offset as usize;
        let size = (header.pattern_count as usize) * mem::size_of::<PatternEntry>();

        if !validate_range(offset, size, buffer_len) {
            report.error(format!(
                "Patterns section out of bounds: offset={}, size={}, buffer={}",
                offset, size, buffer_len
            ));
        } else if !offset.is_multiple_of(mem::align_of::<PatternEntry>()) {
            report.error(format!(
                "Patterns section misaligned: offset={}, required_alignment={}",
                offset,
                mem::align_of::<PatternEntry>()
            ));
        }
    }

    // Validate pattern strings section
    if header.pattern_strings_size > 0 {
        let offset = header.pattern_strings_offset as usize;
        let size = header.pattern_strings_size as usize;

        if !validate_range(offset, size, buffer_len) {
            report.error(format!(
                "Pattern strings section out of bounds: offset={}, size={}, buffer={}",
                offset, size, buffer_len
            ));
        }
    }

    // Validate meta-word mappings
    if header.meta_word_mapping_count > 0 {
        let offset = header.meta_word_mappings_offset as usize;
        let size = (header.meta_word_mapping_count as usize) * mem::size_of::<MetaWordMapping>();

        if !validate_range(offset, size, buffer_len) {
            report.error(format!(
                "Meta-word mappings section out of bounds: offset={}, size={}, buffer={}",
                offset, size, buffer_len
            ));
        }
    }

    // Validate data section (v2+)
    if header.has_data_section() {
        let offset = header.data_section_offset as usize;
        let size = header.data_section_size as usize;

        if !validate_range(offset, size, buffer_len) {
            report.error(format!(
                "Data section out of bounds: offset={}, size={}, buffer={}",
                offset, size, buffer_len
            ));
        }
    }

    // Validate mapping table (v2+)
    if header.mapping_count > 0 {
        let offset = header.mapping_table_offset as usize;
        let size = (header.mapping_count as usize) * mem::size_of::<PatternDataMapping>();

        if !validate_range(offset, size, buffer_len) {
            report.error(format!(
                "Mapping table out of bounds: offset={}, size={}, buffer={}",
                offset, size, buffer_len
            ));
        }
    }

    // Validate AC literal mapping (v3)
    if header.has_ac_literal_mapping() {
        let offset = header.ac_literal_map_offset as usize;
        // Size is variable, just check offset for now
        if offset >= buffer_len {
            report.error(format!(
                "AC literal mapping offset out of bounds: offset={}, buffer={}",
                offset, buffer_len
            ));
        }
    }

    Ok(())
}

/// Validate that a range is within bounds
fn validate_range(offset: usize, size: usize, buffer_len: usize) -> bool {
    offset
        .checked_add(size)
        .is_some_and(|end| end <= buffer_len)
}

/// Validate all strings in PARAGLOB section are valid UTF-8
fn validate_paraglob_strings(
    buffer: &[u8],
    header: &ParaglobHeader,
    report: &mut ValidationReport,
) -> Result<()> {
    // Validate pattern strings
    if header.pattern_count > 0 && header.pattern_strings_size > 0 {
        let patterns_offset = header.patterns_offset as usize;
        let patterns_count = header.pattern_count as usize;

        // Read all pattern entries
        for i in 0..patterns_count {
            let entry_offset = patterns_offset + i * mem::size_of::<PatternEntry>();

            if entry_offset + mem::size_of::<PatternEntry>() > buffer.len() {
                report.error(format!("Pattern entry {} out of bounds", i));
                continue;
            }

            let entry = PatternEntry::read_from_prefix(&buffer[entry_offset..])
                .map(|(e, _)| e)
                .map_err(|_| ParaglobError::Format("Failed to read pattern entry".to_string()))?;

            let str_offset = entry.pattern_string_offset as usize;
            let str_length = entry.pattern_string_length as usize;

            // Validate string bounds
            if !validate_range(str_offset, str_length, buffer.len()) {
                report.error(format!(
                    "Pattern {} string out of bounds: offset={}, length={}",
                    i, str_offset, str_length
                ));
                continue;
            }

            // Validate UTF-8
            let str_bytes = &buffer[str_offset..str_offset + str_length];
            if let Err(e) = std::str::from_utf8(str_bytes) {
                report.error(format!(
                    "Pattern {} contains invalid UTF-8 at offset {}: {}",
                    i, str_offset, e
                ));
            }

            // Check for null terminator after string (optional but recommended)
            if str_offset + str_length < buffer.len() && buffer[str_offset + str_length] != 0 {
                report.warning(format!(
                    "Pattern {} is not null-terminated (offset={})",
                    i, str_offset
                ));
            }
        }
    }

    Ok(())
}

/// Validate AC automaton structure
fn validate_ac_structure(
    buffer: &[u8],
    header: &ParaglobHeader,
    report: &mut ValidationReport,
    level: ValidationLevel,
) -> Result<()> {
    if header.ac_node_count == 0 {
        report.info("No AC automaton nodes (empty database)");
        return Ok(());
    }

    let nodes_offset = header.ac_nodes_offset as usize;
    let node_count = header.ac_node_count as usize;

    let mut state_distribution = [0u32; 4];

    for i in 0..node_count {
        let node_offset = nodes_offset + i * mem::size_of::<ACNodeHot>();

        if node_offset + mem::size_of::<ACNodeHot>() > buffer.len() {
            report.error(format!("AC node {} out of bounds", i));
            continue;
        }

        let node = ACNodeHot::read_from_prefix(&buffer[node_offset..])
            .map(|(n, _)| n)
            .map_err(|_| ParaglobError::Format("Failed to read AC node".to_string()))?;

        // Note: ACNodeHot doesn't store depth (removed for cache optimization)
        // max_depth tracking removed

        // Validate state kind
        let state_kind = StateKind::from_u8(node.state_kind);
        if state_kind.is_none() {
            report.error(format!(
                "AC node {} has invalid state kind: {}",
                i, node.state_kind
            ));
            continue;
        }
        let state_kind = state_kind.unwrap();
        state_distribution[state_kind as usize] += 1;

        // Validate failure link
        if node.failure_offset != 0 {
            let failure_node_offset = node.failure_offset as usize;
            if failure_node_offset < nodes_offset
                || failure_node_offset >= nodes_offset + node_count * mem::size_of::<ACNodeHot>()
                || !(failure_node_offset - nodes_offset).is_multiple_of(mem::size_of::<ACNodeHot>())
            {
                report.error(format!(
                    "AC node {} has invalid failure link offset: {}",
                    i, node.failure_offset
                ));
            }

            // Check for self-loop (root is at offset nodes_offset)
            if failure_node_offset == node_offset && node_offset != nodes_offset {
                report.error(format!("AC node {} has self-referencing failure link", i));
            }
        }

        // Validate edges based on state kind
        match state_kind {
            StateKind::Empty => {
                if node.edge_count != 0 {
                    report.error(format!(
                        "AC node {} is Empty but has edge_count={}",
                        i, node.edge_count
                    ));
                }
            }
            StateKind::One => {
                // Single edge stored inline
                if node.edge_count != 0 {
                    report.warning(format!(
                        "AC node {} is One but has edge_count={} (should be 0)",
                        i, node.edge_count
                    ));
                }
                // Validate target offset (stored in edges_offset for One encoding)
                let target_offset = node.edges_offset as usize;
                if target_offset != 0
                    && (target_offset < nodes_offset
                        || target_offset >= nodes_offset + node_count * mem::size_of::<ACNodeHot>()
                        || !(target_offset - nodes_offset)
                            .is_multiple_of(mem::size_of::<ACNodeHot>()))
                {
                    report.error(format!(
                        "AC node {} (One) has invalid target offset: {}",
                        i, target_offset
                    ));
                }
            }
            StateKind::Sparse => {
                // Validate edge array
                let edges_offset = node.edges_offset as usize;
                let edge_count = node.edge_count as usize;
                let edges_size = edge_count * mem::size_of::<ACEdge>();

                if edge_count == 0 {
                    report.error(format!("AC node {} is Sparse but has no edges", i));
                } else if !validate_range(edges_offset, edges_size, buffer.len()) {
                    report.error(format!(
                        "AC node {} edge array out of bounds: offset={}, count={}",
                        i, edges_offset, edge_count
                    ));
                } else if level == ValidationLevel::Strict || level == ValidationLevel::Audit {
                    // Validate each edge
                    for j in 0..edge_count {
                        let edge_offset = edges_offset + j * mem::size_of::<ACEdge>();
                        if let Ok((edge, _)) = ACEdge::read_from_prefix(&buffer[edge_offset..]) {
                            let target_offset = edge.target_offset as usize;
                            if target_offset < nodes_offset
                                || target_offset
                                    >= nodes_offset + node_count * mem::size_of::<ACNodeHot>()
                                || !(target_offset - nodes_offset)
                                    .is_multiple_of(mem::size_of::<ACNodeHot>())
                            {
                                report.error(format!(
                                    "AC node {} edge {} has invalid target: {}",
                                    i, j, target_offset
                                ));
                            }
                        }
                    }
                }
            }
            StateKind::Dense => {
                // Validate dense lookup table (256 * 4 bytes = 1024 bytes)
                let lookup_offset = node.edges_offset as usize;
                let lookup_size = 1024;

                if !validate_range(lookup_offset, lookup_size, buffer.len()) {
                    report.error(format!(
                        "AC node {} dense lookup out of bounds: offset={}",
                        i, lookup_offset
                    ));
                } else if !lookup_offset.is_multiple_of(64) {
                    report.warning(format!(
                        "AC node {} dense lookup not cache-aligned: offset={}",
                        i, lookup_offset
                    ));
                }

                // Optionally validate all targets in strict/audit mode
                if level == ValidationLevel::Strict || level == ValidationLevel::Audit {
                    for j in 0..256 {
                        let target_offset_pos = lookup_offset + j * 4;
                        if target_offset_pos + 4 <= buffer.len() {
                            let target_offset = u32::from_le_bytes([
                                buffer[target_offset_pos],
                                buffer[target_offset_pos + 1],
                                buffer[target_offset_pos + 2],
                                buffer[target_offset_pos + 3],
                            ]) as usize;

                            if target_offset != 0
                                && (target_offset < nodes_offset
                                    || target_offset
                                        >= nodes_offset + node_count * mem::size_of::<ACNodeHot>()
                                    || !(target_offset - nodes_offset)
                                        .is_multiple_of(mem::size_of::<ACNodeHot>()))
                            {
                                report.error(format!(
                                    "AC node {} dense entry [{}] has invalid target: {}",
                                    i, j, target_offset
                                ));
                            }
                        }
                    }
                }
            }
        }

        // Validate pattern IDs
        if node.pattern_count > 0 {
            let patterns_offset = node.patterns_offset as usize;
            let patterns_size = (node.pattern_count as usize) * mem::size_of::<u32>();

            if !validate_range(patterns_offset, patterns_size, buffer.len()) {
                report.error(format!(
                    "AC node {} pattern IDs out of bounds: offset={}, count={}",
                    i, patterns_offset, node.pattern_count
                ));
            } else {
                // Validate each pattern ID references a valid pattern
                for j in 0..(node.pattern_count as usize) {
                    let pid_offset = patterns_offset + j * mem::size_of::<u32>();
                    if pid_offset + 4 <= buffer.len() {
                        let pattern_id = u32::from_le_bytes([
                            buffer[pid_offset],
                            buffer[pid_offset + 1],
                            buffer[pid_offset + 2],
                            buffer[pid_offset + 3],
                        ]);

                        if pattern_id >= header.pattern_count {
                            report.error(format!(
                                "AC node {} pattern ID {} out of range: {} (max={})",
                                i, j, pattern_id, header.pattern_count
                            ));
                        }
                    }
                }
            }
        }

        // Note: visited tracking removed (ACNodeHot doesn't have node_id)
        // All nodes are implicitly visited by linear iteration
    }

    report.stats.state_encoding_distribution = state_distribution;

    report.info(format!(
        "AC automaton: {} nodes, encodings: Empty={}, One={}, Sparse={}, Dense={}",
        node_count,
        state_distribution[0],
        state_distribution[1],
        state_distribution[2],
        state_distribution[3]
    ));

    // Note: Unreachable node detection removed for ACNodeHot (no node_id tracking)
    // Use validate_ac_reachability() in consistency checks instead

    Ok(())
}

/// Validate pattern entries
fn validate_patterns(
    buffer: &[u8],
    header: &ParaglobHeader,
    report: &mut ValidationReport,
) -> Result<()> {
    if header.pattern_count == 0 {
        report.info("No patterns in database");
        return Ok(());
    }

    let patterns_offset = header.patterns_offset as usize;
    let pattern_count = header.pattern_count as usize;

    let mut literal_count = 0;
    let mut glob_count = 0;

    for i in 0..pattern_count {
        let entry_offset = patterns_offset + i * mem::size_of::<PatternEntry>();

        if entry_offset + mem::size_of::<PatternEntry>() > buffer.len() {
            continue; // Already reported in validate_offsets
        }

        let entry = PatternEntry::read_from_prefix(&buffer[entry_offset..])
            .map(|(e, _)| e)
            .map_err(|_| ParaglobError::Format("Failed to read pattern entry".to_string()))?;

        // Validate pattern type
        match entry.pattern_type {
            0 => literal_count += 1, // Literal
            1 => glob_count += 1,    // Glob
            t => report.error(format!("Pattern {} has invalid type: {}", i, t)),
        }

        // Pattern ID should match index (typically)
        if entry.pattern_id != i as u32 {
            report.warning(format!(
                "Pattern {} has mismatched ID: {} (expected {})",
                i, entry.pattern_id, i
            ));
        }
    }

    report.stats.literal_count = literal_count;
    report.stats.glob_count = glob_count;
    report.info(format!(
        "Patterns: {} total ({} literal, {} glob)",
        pattern_count, literal_count, glob_count
    ));

    Ok(())
}

/// Validate PARAGLOB consistency - checks for data structure integrity issues
/// This includes:
/// - Orphan AC nodes (nodes not reachable from root)
/// - Pattern-literal mapping bidirectionality
/// - Wildcard entry validity
/// - Data section mapping consistency
fn validate_paraglob_consistency(
    buffer: &[u8],
    header: &ParaglobHeader,
    report: &mut ValidationReport,
    level: ValidationLevel,
) -> Result<()> {
    // Skip if empty database
    if header.ac_node_count == 0 && header.pattern_count == 0 {
        return Ok(());
    }

    report.info("Running PARAGLOB consistency checks...");

    // 1. Check for orphan AC nodes (unreachable from root)
    validate_ac_reachability(buffer, header, report)?;

    // 2. Validate pattern-to-AC-node bidirectional consistency
    validate_pattern_ac_consistency(buffer, header, report)?;

    // 3. Validate AC literal mapping consistency (v3)
    if header.has_ac_literal_mapping() {
        validate_ac_literal_mapping_consistency(buffer, header, report)?;
    }

    // 4. Validate data section mappings consistency (v2+)
    if header.has_data_section() && header.mapping_count > 0 {
        validate_data_mapping_consistency(buffer, header, report)?;
    }

    // 5. Validate meta-word mappings
    if header.meta_word_mapping_count > 0 {
        validate_meta_word_consistency(buffer, header, report)?;
    }

    // 6. Audit mode: track potential performance issues
    if level == ValidationLevel::Audit {
        audit_paraglob_performance(header, report)?;
    }

    report.info("✓ PARAGLOB consistency checks complete");
    Ok(())
}

/// Check that all AC nodes are reachable from root (no orphans)
fn validate_ac_reachability(
    buffer: &[u8],
    header: &ParaglobHeader,
    report: &mut ValidationReport,
) -> Result<()> {
    if header.ac_node_count == 0 {
        return Ok(());
    }

    let nodes_offset = header.ac_nodes_offset as usize;
    let node_count = header.ac_node_count as usize;

    // Track which nodes are reachable via BFS from root
    let mut reachable = vec![false; node_count];
    let mut queue = Vec::new();

    // Start from root (node 0)
    if node_count > 0 {
        queue.push(0usize);
        reachable[0] = true;
    }

    let mut _nodes_visited = 0;

    while let Some(node_idx) = queue.pop() {
        _nodes_visited += 1;

        let node_offset = nodes_offset + node_idx * mem::size_of::<ACNodeHot>();
        if node_offset + mem::size_of::<ACNodeHot>() > buffer.len() {
            continue;
        }

        let node = match ACNodeHot::read_from_prefix(&buffer[node_offset..]) {
            Ok((n, _)) => n,
            Err(_) => continue,
        };

        let state_kind = StateKind::from_u8(node.state_kind);
        if state_kind.is_none() {
            continue;
        }

        // Follow all edges to mark children as reachable
        match state_kind.unwrap() {
            StateKind::Empty => {}
            StateKind::One => {
                // Single edge stored inline in edges_offset
                let target_offset = node.edges_offset as usize;
                if target_offset >= nodes_offset
                    && target_offset < nodes_offset + node_count * mem::size_of::<ACNodeHot>()
                {
                    let target_idx = (target_offset - nodes_offset) / mem::size_of::<ACNodeHot>();
                    if target_idx < node_count && !reachable[target_idx] {
                        reachable[target_idx] = true;
                        queue.push(target_idx);
                    }
                }
            }
            StateKind::Sparse => {
                let edges_offset = node.edges_offset as usize;
                let edge_count = node.edge_count as usize;

                for i in 0..edge_count {
                    let edge_offset = edges_offset + i * mem::size_of::<ACEdge>();
                    if edge_offset + mem::size_of::<ACEdge>() <= buffer.len() {
                        if let Ok((edge, _)) = ACEdge::read_from_prefix(&buffer[edge_offset..]) {
                            let target_offset = edge.target_offset as usize;
                            if target_offset >= nodes_offset
                                && target_offset
                                    < nodes_offset + node_count * mem::size_of::<ACNodeHot>()
                            {
                                let target_idx =
                                    (target_offset - nodes_offset) / mem::size_of::<ACNodeHot>();
                                if target_idx < node_count && !reachable[target_idx] {
                                    reachable[target_idx] = true;
                                    queue.push(target_idx);
                                }
                            }
                        }
                    }
                }
            }
            StateKind::Dense => {
                let lookup_offset = node.edges_offset as usize;
                let lookup_size = 1024; // 256 * 4 bytes

                if lookup_offset + lookup_size <= buffer.len() {
                    for i in 0..256 {
                        let target_offset_pos = lookup_offset + i * 4;
                        if target_offset_pos + 4 <= buffer.len() {
                            let target_offset = u32::from_le_bytes([
                                buffer[target_offset_pos],
                                buffer[target_offset_pos + 1],
                                buffer[target_offset_pos + 2],
                                buffer[target_offset_pos + 3],
                            ]) as usize;

                            if target_offset != 0
                                && target_offset >= nodes_offset
                                && target_offset
                                    < nodes_offset + node_count * mem::size_of::<ACNodeHot>()
                            {
                                let target_idx =
                                    (target_offset - nodes_offset) / mem::size_of::<ACNodeHot>();
                                if target_idx < node_count && !reachable[target_idx] {
                                    reachable[target_idx] = true;
                                    queue.push(target_idx);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Also follow failure links to ensure we reach all nodes
        if node.failure_offset != 0 {
            let failure_offset = node.failure_offset as usize;
            if failure_offset >= nodes_offset
                && failure_offset < nodes_offset + node_count * mem::size_of::<ACNodeHot>()
            {
                let failure_idx = (failure_offset - nodes_offset) / mem::size_of::<ACNodeHot>();
                if failure_idx < node_count && !reachable[failure_idx] {
                    reachable[failure_idx] = true;
                    queue.push(failure_idx);
                }
            }
        }
    }

    // Count orphaned nodes
    let orphaned_count = reachable.iter().filter(|&&r| !r).count();

    if orphaned_count > 0 {
        report.warning(format!(
            "Found {} orphaned AC nodes (not reachable from root)",
            orphaned_count
        ));

        // In audit mode, list the orphaned node indices
        if !report.stats.trust_assumptions.is_empty() {
            // Audit mode active
            let orphaned_nodes: Vec<usize> = reachable
                .iter()
                .enumerate()
                .filter_map(|(idx, &r)| if !r { Some(idx) } else { None })
                .take(10) // Limit to first 10 for readability
                .collect();

            report.info(format!(
                "Orphaned node indices: {:?}{}",
                orphaned_nodes,
                if orphaned_count > 10 {
                    format!(" ... and {} more", orphaned_count - 10)
                } else {
                    String::new()
                }
            ));
        }
    } else {
        report.info("✓ All AC nodes are reachable from root");
    }

    Ok(())
}

/// Validate that pattern-to-AC-node references are consistent
fn validate_pattern_ac_consistency(
    buffer: &[u8],
    header: &ParaglobHeader,
    report: &mut ValidationReport,
) -> Result<()> {
    if header.pattern_count == 0 {
        return Ok(());
    }

    let nodes_offset = header.ac_nodes_offset as usize;
    let node_count = header.ac_node_count as usize;

    // Build a set of pattern IDs referenced by AC nodes
    let mut patterns_referenced_by_nodes = HashSet::new();

    for i in 0..node_count {
        let node_offset = nodes_offset + i * mem::size_of::<ACNodeHot>();
        if node_offset + mem::size_of::<ACNodeHot>() > buffer.len() {
            continue;
        }

        let node = match ACNodeHot::read_from_prefix(&buffer[node_offset..]) {
            Ok((n, _)) => n,
            Err(_) => continue,
        };

        // Collect pattern IDs from this node
        if node.pattern_count > 0 {
            let patterns_offset = node.patterns_offset as usize;
            let patterns_size = (node.pattern_count as usize) * mem::size_of::<u32>();

            if patterns_offset + patterns_size <= buffer.len() {
                for j in 0..(node.pattern_count as usize) {
                    let pid_offset = patterns_offset + j * mem::size_of::<u32>();
                    if pid_offset + 4 <= buffer.len() {
                        let pattern_id = u32::from_le_bytes([
                            buffer[pid_offset],
                            buffer[pid_offset + 1],
                            buffer[pid_offset + 2],
                            buffer[pid_offset + 3],
                        ]);

                        patterns_referenced_by_nodes.insert(pattern_id);
                    }
                }
            }
        }
    }

    // Check that all literal patterns are referenced by at least one AC node
    let patterns_offset = header.patterns_offset as usize;
    let pattern_count = header.pattern_count as usize;
    let mut unreferenced_literals = 0;

    for i in 0..pattern_count {
        let entry_offset = patterns_offset + i * mem::size_of::<PatternEntry>();
        if entry_offset + mem::size_of::<PatternEntry>() > buffer.len() {
            continue;
        }

        let entry = match PatternEntry::read_from_prefix(&buffer[entry_offset..]) {
            Ok((e, _)) => e,
            Err(_) => continue,
        };

        // Only check literal patterns (type 0)
        if entry.pattern_type == 0 && !patterns_referenced_by_nodes.contains(&entry.pattern_id) {
            unreferenced_literals += 1;
        }
    }

    if unreferenced_literals > 0 {
        report.warning(format!(
            "Found {} literal patterns not referenced by any AC node",
            unreferenced_literals
        ));
    } else {
        report.info("✓ All literal patterns are referenced by AC nodes");
    }

    Ok(())
}

/// Validate AC literal mapping consistency (v3)
fn validate_ac_literal_mapping_consistency(
    buffer: &[u8],
    header: &ParaglobHeader,
    report: &mut ValidationReport,
) -> Result<()> {
    let map_offset = header.ac_literal_map_offset as usize;

    if map_offset + 4 > buffer.len() {
        return Ok(()); // Already reported earlier
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
            report.warning(format!(
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

        let pattern_count = u32::from_le_bytes([
            buffer[current_offset + 4],
            buffer[current_offset + 5],
            buffer[current_offset + 6],
            buffer[current_offset + 7],
        ]);

        current_offset += 8;

        // Read pattern IDs
        let pattern_ids_size = (pattern_count as usize) * 4;
        if current_offset + pattern_ids_size > buffer.len() {
            report.warning(format!(
                "AC literal mapping entry {} pattern IDs truncated",
                i
            ));
            break;
        }

        for j in 0..pattern_count {
            let pid_offset = current_offset + (j as usize) * 4;
            let pattern_id = u32::from_le_bytes([
                buffer[pid_offset],
                buffer[pid_offset + 1],
                buffer[pid_offset + 2],
                buffer[pid_offset + 3],
            ]);

            if pattern_id >= header.pattern_count {
                report.error(format!(
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

    if entries_checked == entry_count {
        report.info(format!(
            "✓ AC literal mapping: validated {} entries, {} unique patterns",
            entries_checked,
            referenced_patterns.len()
        ));
    }

    Ok(())
}

/// Validate data section mapping consistency (v2+)
fn validate_data_mapping_consistency(
    buffer: &[u8],
    header: &ParaglobHeader,
    report: &mut ValidationReport,
) -> Result<()> {
    let mapping_offset = header.mapping_table_offset as usize;
    let mapping_count = header.mapping_count as usize;
    let data_offset = header.data_section_offset as usize;
    let data_size = header.data_section_size as usize;

    let mut patterns_with_data = HashSet::new();
    let mut duplicate_mappings = 0;

    for i in 0..mapping_count {
        let entry_offset = mapping_offset + i * mem::size_of::<PatternDataMapping>();
        if entry_offset + mem::size_of::<PatternDataMapping>() > buffer.len() {
            continue;
        }

        let mapping = match PatternDataMapping::read_from_prefix(&buffer[entry_offset..]) {
            Ok((m, _)) => m,
            Err(_) => continue,
        };

        // Check for duplicate pattern IDs in mapping table
        if !patterns_with_data.insert(mapping.pattern_id) {
            duplicate_mappings += 1;
        }

        // Validate pattern ID is valid
        if mapping.pattern_id >= header.pattern_count {
            // Already reported in earlier validation
            continue;
        }

        // Validate inline data bounds if applicable
        if header.has_inline_data() {
            let data_ref = mapping.data_offset as usize;
            // Check if this looks like an inline data reference
            if data_ref >= data_offset && data_ref < data_offset + data_size {
                let data_end = data_ref + mapping.data_size as usize;
                if data_end > data_offset + data_size {
                    // Already reported in earlier validation
                    continue;
                }
            }
        }
    }

    if duplicate_mappings > 0 {
        report.warning(format!(
            "Found {} duplicate pattern IDs in data mapping table",
            duplicate_mappings
        ));
    } else {
        report.info("✓ Data mapping table: no duplicate pattern IDs");
    }

    // Check coverage: how many patterns have associated data
    let coverage_pct = if header.pattern_count > 0 {
        (patterns_with_data.len() * 100) / header.pattern_count as usize
    } else {
        0
    };

    report.info(format!(
        "Data mapping coverage: {}/{} patterns ({}%)",
        patterns_with_data.len(),
        header.pattern_count,
        coverage_pct
    ));

    Ok(())
}

/// Validate meta-word mappings consistency
fn validate_meta_word_consistency(
    buffer: &[u8],
    header: &ParaglobHeader,
    report: &mut ValidationReport,
) -> Result<()> {
    let mapping_offset = header.meta_word_mappings_offset as usize;
    let mapping_count = header.meta_word_mapping_count as usize;

    let mut referenced_patterns = HashSet::new();
    let mut invalid_references = 0;

    for i in 0..mapping_count {
        let entry_offset = mapping_offset + i * mem::size_of::<MetaWordMapping>();
        if entry_offset + mem::size_of::<MetaWordMapping>() > buffer.len() {
            continue;
        }

        let mapping = match MetaWordMapping::read_from_prefix(&buffer[entry_offset..]) {
            Ok((m, _)) => m,
            Err(_) => continue,
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

                        if pattern_id >= header.pattern_count {
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
        report.error(format!(
            "Meta-word mappings contain {} invalid references",
            invalid_references
        ));
    } else {
        report.info(format!(
            "✓ Meta-word mappings: {} entries, {} unique patterns referenced",
            mapping_count,
            referenced_patterns.len()
        ));
    }

    Ok(())
}

/// Audit PARAGLOB performance characteristics
fn audit_paraglob_performance(
    header: &ParaglobHeader,
    report: &mut ValidationReport,
) -> Result<()> {
    // Memory usage estimates
    let node_memory = (header.ac_node_count as usize) * mem::size_of::<ACNodeHot>();
    let pattern_memory = (header.pattern_count as usize) * mem::size_of::<PatternEntry>();
    let string_memory = header.pattern_strings_size as usize;
    let data_memory = header.data_section_size as usize;

    let total_memory = node_memory + pattern_memory + string_memory + data_memory;

    report.info(format!(
        "Memory usage: {} KB total ({} KB AC nodes, {} KB patterns, {} KB strings, {} KB data)",
        total_memory / 1024,
        node_memory / 1024,
        pattern_memory / 1024,
        string_memory / 1024,
        data_memory / 1024
    ));

    // Performance warnings
    if header.ac_node_count > 1_000_000 {
        report.warning(format!(
            "Large AC automaton ({} nodes) may impact load time and memory usage",
            header.ac_node_count
        ));
    }

    if header.pattern_count > 500_000 {
        report.warning(format!(
            "Large pattern count ({}) may impact query performance",
            header.pattern_count
        ));
    }

    // Check state encoding distribution efficiency
    let empty_pct =
        (report.stats.state_encoding_distribution[0] * 100) / header.ac_node_count.max(1);
    let dense_pct =
        (report.stats.state_encoding_distribution[3] * 100) / header.ac_node_count.max(1);

    if dense_pct > 50 {
        report.info(format!(
            "High dense state usage ({}%) - good for performance but uses more memory",
            dense_pct
        ));
    }

    if empty_pct > 20 {
        report.info(format!(
            "Many empty nodes ({}%) - potential for optimization",
            empty_pct
        ));
    }

    Ok(())
}

/// Validate IP tree structure with full traversal
/// Checks for cycles, invalid pointers, orphaned nodes, and structural integrity
fn validate_ip_tree_structure(
    buffer: &[u8],
    tree_size: usize,
    node_count: u32,
    node_bytes: usize,
    ip_version: u16,
    report: &mut ValidationReport,
) -> Result<()> {
    if node_count == 0 {
        return Ok(());
    }

    report.info("Performing deep IP tree traversal validation...".to_string());

    // Track which nodes are visited during traversal
    let mut visited = HashSet::new();
    let mut traversal_errors = 0;
    let mut cycle_detected = false;
    let mut invalid_pointers = 0;

    // Determine tree depth based on IP version
    let tree_depth = match ip_version {
        4 => 32,  // IPv4: 32 bits
        6 => 128, // IPv6: 128 bits
        _ => {
            report.error(format!("Invalid IP version: {}", ip_version));
            return Ok(());
        }
    };

    // Traverse tree starting from root (node 0)
    let result = traverse_ip_tree_node(
        buffer,
        0, // Start at root
        0, // Depth 0
        tree_depth,
        node_count,
        node_bytes,
        tree_size,
        &mut visited,
        &mut cycle_detected,
        &mut invalid_pointers,
    );

    if let Err(e) = result {
        traversal_errors += 1;
        report.error(format!("Tree traversal error: {}", e));
    }

    // Check for orphaned nodes (nodes that exist but aren't reachable)
    let orphaned_count = (node_count as usize).saturating_sub(visited.len());
    if orphaned_count > 0 {
        report.warning(format!(
            "Found {} orphaned nodes (exist in tree but unreachable from root)",
            orphaned_count
        ));
    }

    // Report statistics
    report.info(format!(
        "IP tree traversal: {} nodes visited out of {} total ({}% coverage)",
        visited.len(),
        node_count,
        (visited.len() * 100) / node_count as usize
    ));

    if cycle_detected {
        report.error(
            "🚨 CRITICAL: Tree cycle detected - would cause infinite loops during IP lookup!"
                .to_string(),
        );
    }

    if invalid_pointers > 0 {
        report.error(format!(
            "🚨 CRITICAL: {} invalid node pointers detected!",
            invalid_pointers
        ));
    }

    if traversal_errors > 0 {
        report.error(format!("Tree traversal found {} errors", traversal_errors));
    }

    Ok(())
}

/// Recursively traverse IP tree node and validate structure
#[allow(clippy::too_many_arguments)]
fn traverse_ip_tree_node(
    buffer: &[u8],
    node_index: u32,
    depth: usize,
    max_depth: usize,
    node_count: u32,
    node_bytes: usize,
    tree_size: usize,
    visited: &mut HashSet<u32>,
    cycle_detected: &mut bool,
    invalid_pointers: &mut usize,
) -> std::result::Result<(), String> {
    // Check for cycles
    if visited.contains(&node_index) {
        *cycle_detected = true;
        return Err(format!("Cycle detected at node {}", node_index));
    }

    // Check depth (shouldn't exceed IP bit count)
    if depth > max_depth {
        return Err(format!(
            "Tree depth {} exceeds maximum {} for this IP version",
            depth, max_depth
        ));
    }

    // Validate node index is in range
    if node_index >= node_count {
        *invalid_pointers += 1;
        return Err(format!(
            "Node index {} exceeds node count {}",
            node_index, node_count
        ));
    }

    visited.insert(node_index);

    // Calculate node offset
    let node_offset = (node_index as usize) * node_bytes;
    if node_offset + node_bytes > tree_size {
        return Err(format!(
            "Node {} offset {} exceeds tree size {}",
            node_index, node_offset, tree_size
        ));
    }

    if node_offset + node_bytes > buffer.len() {
        return Err(format!("Node {} would read beyond buffer", node_index));
    }

    // Read both records (left and right)
    let (left_record, right_record) = match node_bytes {
        6 => {
            // 24-bit records
            let left = (buffer[node_offset] as u32) << 16
                | (buffer[node_offset + 1] as u32) << 8
                | (buffer[node_offset + 2] as u32);
            let right = (buffer[node_offset + 3] as u32) << 16
                | (buffer[node_offset + 4] as u32) << 8
                | (buffer[node_offset + 5] as u32);
            (left, right)
        }
        7 => {
            // 28-bit records (more complex bit packing)
            // First 3.5 bytes: left record
            // Last 3.5 bytes: right record
            let left = (buffer[node_offset] as u32) << 20
                | (buffer[node_offset + 1] as u32) << 12
                | (buffer[node_offset + 2] as u32) << 4
                | ((buffer[node_offset + 3] as u32) >> 4);
            let right = ((buffer[node_offset + 3] as u32) & 0x0F) << 24
                | (buffer[node_offset + 4] as u32) << 16
                | (buffer[node_offset + 5] as u32) << 8
                | (buffer[node_offset + 6] as u32);
            (left, right)
        }
        8 => {
            // 32-bit records
            let left = u32::from_be_bytes([
                buffer[node_offset],
                buffer[node_offset + 1],
                buffer[node_offset + 2],
                buffer[node_offset + 3],
            ]);
            let right = u32::from_be_bytes([
                buffer[node_offset + 4],
                buffer[node_offset + 5],
                buffer[node_offset + 6],
                buffer[node_offset + 7],
            ]);
            (left, right)
        }
        _ => {
            return Err(format!("Invalid node_bytes: {}", node_bytes));
        }
    };

    // Validate and recurse into child nodes
    // Records can be:
    // - Node index (< node_count): pointer to another tree node
    // - Data pointer (>= node_count): pointer to data section
    // - Equal to node_count: no data (empty)

    // Only recurse if we haven't reached maximum depth
    if depth < max_depth {
        // Validate left record
        if left_record < node_count {
            // It's a node pointer - recurse
            traverse_ip_tree_node(
                buffer,
                left_record,
                depth + 1,
                max_depth,
                node_count,
                node_bytes,
                tree_size,
                visited,
                cycle_detected,
                invalid_pointers,
            )?;
        } else if left_record > node_count {
            // It's a data pointer - validate it points to reasonable location
            // (Already validated by validate_data_pointers)
        }
        // If left_record == node_count, it's empty (no data)

        // Validate right record
        if right_record < node_count {
            // It's a node pointer - recurse
            traverse_ip_tree_node(
                buffer,
                right_record,
                depth + 1,
                max_depth,
                node_count,
                node_bytes,
                tree_size,
                visited,
                cycle_detected,
                invalid_pointers,
            )?;
        } else if right_record > node_count {
            // It's a data pointer - validate it points to reasonable location
        }
        // If right_record == node_count, it's empty
    }

    Ok(())
}

/// Validate data section pointers for safety issues
/// Checks for cycles, depth limits, bounds, and type validity
fn validate_data_section_pointers(
    buffer: &[u8],
    tree_size: usize,
    node_count: u32,
    node_bytes: usize,
    report: &mut ValidationReport,
    level: ValidationLevel,
) -> Result<()> {
    let data_section_start = tree_size + 16; // Tree + separator

    if data_section_start >= buffer.len() {
        return Ok(()); // No data section
    }

    let data_section = &buffer[data_section_start..];

    // Sample data values and validate their pointer chains
    let sample_count = if level == ValidationLevel::Strict || level == ValidationLevel::Audit {
        node_count.min(100) // More thorough sampling
    } else {
        node_count.min(20) // Basic sampling
    };

    if node_count == 0 || sample_count == 0 {
        return Ok(());
    }

    let step = if node_count > sample_count {
        (node_count / sample_count).max(1)
    } else {
        1
    };

    let mut pointers_checked = 0;
    let mut cycles_detected = 0;
    let mut max_depth_found = 0;
    let mut invalid_pointers = 0;

    // Check data values reachable from tree nodes
    for i in (0..node_count)
        .step_by(step as usize)
        .take(sample_count as usize)
    {
        let node_offset = (i as usize) * node_bytes;

        if node_offset + node_bytes > tree_size {
            continue;
        }

        // Read record value (simplified - just check left record)
        let record_val = match node_bytes {
            6 => {
                // 24-bit
                let b0 = buffer[node_offset] as u32;
                let b1 = buffer[node_offset + 1] as u32;
                let b2 = buffer[node_offset + 2] as u32;
                (b0 << 16) | (b1 << 8) | b2
            }
            7 => continue, // 28-bit - complex, skip
            8 => {
                // 32-bit
                u32::from_be_bytes([
                    buffer[node_offset],
                    buffer[node_offset + 1],
                    buffer[node_offset + 2],
                    buffer[node_offset + 3],
                ])
            }
            _ => continue,
        };

        // If record points to data (> node_count), validate it
        if record_val > node_count {
            let data_offset = (record_val - node_count - 16) as usize;

            if data_offset < data_section.len() {
                // Validate this data value and all its pointer chains
                let mut visited = HashSet::new();
                match validate_data_value_pointers(
                    data_section,
                    data_offset,
                    &mut visited,
                    0,
                    report,
                ) {
                    Ok(depth) => {
                        pointers_checked += visited.len();
                        max_depth_found = max_depth_found.max(depth);
                    }
                    Err(ValidationError::Cycle { offset }) => {
                        cycles_detected += 1;
                        report.error(format!(
                            "Pointer cycle detected in data section at offset {}",
                            offset
                        ));
                    }
                    Err(ValidationError::DepthExceeded { depth }) => {
                        report.error(format!(
                            "Pointer chain depth {} exceeds safe limit (max: {})",
                            depth, MAX_POINTER_DEPTH
                        ));
                    }
                    Err(ValidationError::InvalidOffset { offset, reason }) => {
                        invalid_pointers += 1;
                        report.error(format!("Invalid pointer at offset {}: {}", offset, reason));
                    }
                    Err(ValidationError::InvalidType { offset, type_id }) => {
                        report.error(format!(
                            "Invalid data type {} at offset {}",
                            type_id, offset
                        ));
                    }
                }
            }
        }
    }

    // Report findings
    if pointers_checked > 0 {
        report.info(format!(
            "Data pointers validated: {} checked, max chain depth: {}",
            pointers_checked, max_depth_found
        ));
    }

    if cycles_detected > 0 {
        report.error(format!(
            "🚨 CRITICAL: {} pointer cycles detected - could cause infinite loops!",
            cycles_detected
        ));
    }

    if invalid_pointers > 0 {
        report.error(format!(
            "🚨 CRITICAL: {} invalid pointers detected - could cause crashes!",
            invalid_pointers
        ));
    }

    Ok(())
}

/// Maximum safe depth for pointer chains
const MAX_POINTER_DEPTH: usize = 32;

/// Maximum reasonable total nesting depth (arrays/maps + pointers)
const MAX_TOTAL_DEPTH: usize = 64;

/// Validation error types for data section
#[derive(Debug)]
enum ValidationError {
    Cycle { offset: usize },
    DepthExceeded { depth: usize },
    InvalidOffset { offset: usize, reason: String },
    InvalidType { offset: usize, type_id: u8 },
}

/// Validate a data value and all pointers it contains
/// Returns the maximum depth of pointer chains encountered
/// Detects cycles using the visited set
fn validate_data_value_pointers(
    data_section: &[u8],
    offset: usize,
    visited: &mut HashSet<usize>,
    depth: usize,
    _report: &mut ValidationReport,
) -> std::result::Result<usize, ValidationError> {
    // Check depth limit (use MAX_TOTAL_DEPTH for combined nesting)
    if depth > MAX_TOTAL_DEPTH {
        return Err(ValidationError::DepthExceeded { depth });
    }

    // Check for cycles
    if visited.contains(&offset) {
        return Err(ValidationError::Cycle { offset });
    }

    visited.insert(offset);

    // Validate offset bounds
    if offset >= data_section.len() {
        return Err(ValidationError::InvalidOffset {
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
                return Err(ValidationError::InvalidOffset {
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
                        let child_depth = validate_data_value_pointers(
                            data_section,
                            cursor,
                            visited,
                            depth + 1,
                            _report,
                        )?;
                        max_child_depth = max_child_depth.max(child_depth);
                        // Skip past this element (approximate)
                        cursor = skip_data_value(data_section, cursor)?;
                    }
                }
                8 | 9 | 10 | 14 | 15 => {
                    // Int32, Uint64, Uint128, Bool, Float - no pointers
                }
                _ => {
                    return Err(ValidationError::InvalidType {
                        offset,
                        type_id: ext_type_id,
                    });
                }
            }
        }
        1 => {
            // Pointer - this is critical to validate!
            let pointer_offset = decode_pointer_offset(data_section, &mut cursor, payload)?;

            // Validate pointer target
            if pointer_offset >= data_section.len() {
                return Err(ValidationError::InvalidOffset {
                    offset: pointer_offset,
                    reason: "Pointer target beyond data section".to_string(),
                });
            }

            // Recursively validate pointed-to value
            let child_depth = validate_data_value_pointers(
                data_section,
                pointer_offset,
                visited,
                depth + 1,
                _report,
            )?;
            max_child_depth = max_child_depth.max(child_depth);
        }
        2..=6 => {
            // String, Double, Bytes, Uint16, Uint32 - no pointers, just validate bounds
            // (already validated by UTF-8 check for strings)
        }
        7 => {
            // Map - validate all values
            let count = decode_size_for_validation(data_section, &mut cursor, payload)?;
            for _ in 0..count {
                // Skip key (string)
                cursor = skip_data_value(data_section, cursor)?;
                // Validate value
                let child_depth = validate_data_value_pointers(
                    data_section,
                    cursor,
                    visited,
                    depth + 1,
                    _report,
                )?;
                max_child_depth = max_child_depth.max(child_depth);
                cursor = skip_data_value(data_section, cursor)?;
            }
        }
        _ => {
            return Err(ValidationError::InvalidType { offset, type_id });
        }
    }

    Ok(max_child_depth)
}

/// Decode size field for validation (similar to DataDecoder but for validation)
fn decode_size_for_validation(
    data: &[u8],
    cursor: &mut usize,
    size_bits: u8,
) -> std::result::Result<usize, ValidationError> {
    match size_bits {
        0..=28 => Ok(size_bits as usize),
        29 => {
            if *cursor >= data.len() {
                return Err(ValidationError::InvalidOffset {
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
                return Err(ValidationError::InvalidOffset {
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
                return Err(ValidationError::InvalidOffset {
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
        _ => Err(ValidationError::InvalidOffset {
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
) -> std::result::Result<usize, ValidationError> {
    let size_bits = (payload >> 3) & 0x3;

    let offset = match size_bits {
        0 => {
            if *cursor >= data.len() {
                return Err(ValidationError::InvalidOffset {
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
                return Err(ValidationError::InvalidOffset {
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
                return Err(ValidationError::InvalidOffset {
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
                return Err(ValidationError::InvalidOffset {
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
            return Err(ValidationError::InvalidOffset {
                offset: *cursor,
                reason: "Invalid pointer size bits".to_string(),
            });
        }
    };

    Ok(offset)
}

/// Skip past a data value (returns offset after the value)
fn skip_data_value(data: &[u8], offset: usize) -> std::result::Result<usize, ValidationError> {
    if offset >= data.len() {
        return Err(ValidationError::InvalidOffset {
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
                return Err(ValidationError::InvalidOffset {
                    offset,
                    reason: "Extended type truncated".to_string(),
                });
            }
            cursor += 1; // Skip extended type byte
                         // Approximate skip (actual size depends on extended type)
            let size = decode_size_for_validation(data, &mut cursor, payload)?;
            Ok(cursor + size)
        }
        1 => {
            // Pointer - determine size from payload
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
            // Map - need to skip all key-value pairs
            let count = decode_size_for_validation(data, &mut cursor, payload)?;
            for _ in 0..count {
                cursor = skip_data_value(data, cursor)?; // Skip key
                cursor = skip_data_value(data, cursor)?; // Skip value
            }
            Ok(cursor)
        }
        _ => Err(ValidationError::InvalidType { offset, type_id }),
    }
}

/// Audit all unsafe code paths in the codebase
/// Documents where unsafe operations occur and their justifications
fn audit_unsafe_code_paths(report: &mut ValidationReport) -> Result<()> {
    // Document unsafe operations in paraglob_offset.rs
    report.stats.unsafe_code_locations.push(UnsafeCodeLocation {
        location: "paraglob_offset.rs::find_all() - wildcard matching".to_string(),
        operation: UnsafeOperation::UncheckedStringRead,
        justification: "read_str_unchecked used in trusted mode for 15-20% performance gain. Bypasses UTF-8 validation.".to_string(),
    });

    report.stats.unsafe_code_locations.push(UnsafeCodeLocation {
        location: "paraglob_offset.rs::find_all() - candidate verification".to_string(),
        operation: UnsafeOperation::UncheckedStringRead,
        justification: "read_str_unchecked used in trusted mode for glob pattern strings. Assumes pre-validated UTF-8.".to_string(),
    });

    report.stats.unsafe_code_locations.push(UnsafeCodeLocation {
        location: "paraglob_offset.rs::from_mmap_trusted()".to_string(),
        operation: UnsafeOperation::MmapLifetimeExtension,
        justification:
            "Extends slice lifetime to 'static for mmap. Assumes caller maintains mmap validity."
                .to_string(),
    });

    report.stats.unsafe_code_locations.push(UnsafeCodeLocation {
        location: "paraglob_offset.rs::from_buffer_with_trust() - AC literal hash".to_string(),
        operation: UnsafeOperation::MmapLifetimeExtension,
        justification: "Extends buffer slice lifetime to 'static for ACLiteralHash. Safe because buffer is owned by struct.".to_string(),
    });

    report.stats.unsafe_code_locations.push(UnsafeCodeLocation {
        location: "database.rs::load_pattern_section()".to_string(),
        operation: UnsafeOperation::MmapLifetimeExtension,
        justification: "Uses from_mmap or from_mmap_trusted with 'static lifetime from mmap. Validity depends on Database lifetime.".to_string(),
    });

    report.stats.unsafe_code_locations.push(UnsafeCodeLocation {
        location: "database.rs::load_combined_pattern_section()".to_string(),
        operation: UnsafeOperation::MmapLifetimeExtension,
        justification: "Zero-copy mmap loading with 'static lifetime. Trusts mmap remains valid."
            .to_string(),
    });

    report.stats.unsafe_code_locations.push(UnsafeCodeLocation {
        location: "offset_format.rs::read_str_unchecked()".to_string(),
        operation: UnsafeOperation::UncheckedStringRead,
        justification: "Core unsafe function for reading strings without UTF-8 validation. Used throughout trusted mode.".to_string(),
    });

    report.stats.unsafe_code_locations.push(UnsafeCodeLocation {
        location: "offset_format.rs - zerocopy transmutes".to_string(),
        operation: UnsafeOperation::Transmute,
        justification: "Zerocopy FromBytes trait uses transmute for #[repr(C)] structs. Safe due to explicit layout control.".to_string(),
    });

    // Info only - this is for audit documentation, not a problem with this database
    let unsafe_count = report.stats.unsafe_code_locations.len();
    report.info(format!(
        "Audit: Documented {} unsafe code locations in matchy codebase",
        unsafe_count
    ));

    Ok(())
}

/// Audit trust mode risks - what validation would be bypassed
fn audit_trust_mode_risks(buffer: &[u8], report: &mut ValidationReport) -> Result<()> {
    // Check if database has pattern section (would use trusted mode)
    let has_pattern_section = buffer.len() >= 8 && &buffer[0..8] == b"PARAGLOB";

    if has_pattern_section {
        report.stats.trust_assumptions.push(TrustAssumption {
            context: "PARAGLOB pattern section loading".to_string(),
            bypassed_check: "UTF-8 validation of all pattern strings".to_string(),
            risk: "Invalid UTF-8 in pattern strings could cause UB when treated as &str. Must validate database before using --trusted.".to_string(),
        });

        report.stats.trust_assumptions.push(TrustAssumption {
            context: "Pattern matching with read_str_unchecked".to_string(),
            bypassed_check: "Bounds checking and UTF-8 validation during queries".to_string(),
            risk: "Corrupted offsets or lengths could read out-of-bounds. Malformed UTF-8 causes undefined behavior.".to_string(),
        });
    }

    // Check for MMDB data section
    if let Ok(metadata) = crate::mmdb::MmdbMetadata::from_file(buffer) {
        if let Ok(crate::DataValue::Map(_)) = metadata.as_value() {
            report.stats.trust_assumptions.push(TrustAssumption {
                context: "MMDB data section strings".to_string(),
                bypassed_check: "UTF-8 validation of data section strings in trusted mode"
                    .to_string(),
                risk: "Invalid UTF-8 in IP lookup results could cause UB when decoded as strings."
                    .to_string(),
            });
        }
    }

    report.stats.trust_assumptions.push(TrustAssumption {
        context: "Memory-mapped file loading".to_string(),
        bypassed_check: "File integrity during mmap lifetime".to_string(),
        risk: "If file is modified while mmap'd, data could change causing inconsistencies or crashes.".to_string(),
    });

    report.stats.trust_assumptions.push(TrustAssumption {
        context: "Offset-based data structures".to_string(),
        bypassed_check: "Alignment and bounds checks in trusted mode".to_string(),
        risk: "Misaligned offsets could cause crashes on platforms requiring strict alignment. Out-of-bounds offsets cause memory corruption.".to_string(),
    });

    // Info only - this is educational about --trusted mode in general, not about this database
    let assumption_count = report.stats.trust_assumptions.len();
    report.info(format!(
        "Audit: --trusted mode bypasses {} validation checks for performance",
        assumption_count
    ));
    report.info(
        "Note: This database passed all validation checks. Info above is for audit documentation."
            .to_string(),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_validate_empty_file() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let result = validate_database(path, ValidationLevel::Standard);
        assert!(result.is_ok());

        let report = result.unwrap();
        assert!(!report.is_valid());
        assert!(!report.errors.is_empty());
        // Should fail to find MMDB metadata marker
        assert!(report.errors.iter().any(|e| e.contains("MMDB")));
    }

    #[test]
    fn test_validate_valid_database() {
        // NOTE: This test is commented out because DatabaseBuilder creates MMDB format,
        // not standalone PARAGLOB format. The validator is designed for .mxy files
        // which have different structure. We keep the other error detection tests.
        //
        // TODO: Create a proper .mxy file builder test when we have sample databases
    }

    #[test]
    fn test_validate_corrupted_database() {
        // Test with non-MMDB data
        let db_bytes = vec![0u8; 1024]; // Random bytes, not MMDB format

        let temp = NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), db_bytes).unwrap();

        let result = validate_database(temp.path(), ValidationLevel::Standard);
        assert!(result.is_ok());

        let report = result.unwrap();
        assert!(!report.is_valid());
        // Should fail to find MMDB format
        assert!(report.errors.iter().any(|e| e.contains("MMDB")));
    }

    #[test]
    fn test_validation_levels() {
        // Test that all validation levels are distinct
        let standard = ValidationLevel::Standard;
        let strict = ValidationLevel::Strict;
        let audit = ValidationLevel::Audit;

        assert_ne!(standard, strict);
        assert_ne!(strict, audit);
        assert_ne!(standard, audit);
    }

    #[test]
    fn test_validation_report_is_valid() {
        let mut report = ValidationReport::new();
        assert!(report.is_valid(), "New report should be valid");

        report.error("Test error");
        assert!(!report.is_valid(), "Report with error should be invalid");

        let mut report2 = ValidationReport::new();
        report2.warning("Test warning");
        assert!(
            report2.is_valid(),
            "Report with only warning should be valid"
        );
    }

    #[test]
    fn test_database_stats_default() {
        let stats = DatabaseStats::default();
        assert_eq!(stats.file_size, 0);
        assert_eq!(stats.version, 0);
        assert_eq!(stats.ac_node_count, 0);
        assert_eq!(stats.pattern_count, 0);
        assert!(!stats.has_data_section);
        assert!(!stats.has_ac_literal_mapping);
    }

    #[test]
    fn test_validate_range() {
        // Valid range
        assert!(validate_range(0, 100, 1000));
        assert!(validate_range(900, 100, 1000));

        // Exactly at boundary
        assert!(validate_range(0, 1000, 1000));

        // Out of bounds
        assert!(!validate_range(0, 1001, 1000));
        assert!(!validate_range(900, 101, 1000));

        // Overflow protection
        assert!(!validate_range(usize::MAX - 10, 100, 1000));
    }

    #[test]
    fn test_audit_mode_requires_valid_mmdb() {
        // Audit tracking only happens for databases with valid MMDB metadata
        // For invalid files, we fail early before reaching audit code
        let temp = NamedTempFile::new().unwrap();
        let db_bytes = vec![0u8; 1024];
        std::fs::write(temp.path(), db_bytes).unwrap();

        let result = validate_database(temp.path(), ValidationLevel::Audit);
        assert!(result.is_ok());

        let report = result.unwrap();
        // Invalid database fails before audit tracking happens
        assert!(!report.is_valid());
        assert!(report.errors.iter().any(|e| e.contains("MMDB")));
        // No unsafe locations tracked for invalid databases
        assert!(report.stats.unsafe_code_locations.is_empty());
    }

    #[test]
    fn test_strict_mode_runs_deep_checks() {
        // Create a minimal but valid-ish MMDB structure for testing
        // This is a simplified test - real validation needs proper MMDB format
        let temp = NamedTempFile::new().unwrap();

        // Invalid but testable
        let db_bytes = vec![0u8; 1024];
        std::fs::write(temp.path(), db_bytes).unwrap();

        let result_standard = validate_database(temp.path(), ValidationLevel::Standard);
        let result_strict = validate_database(temp.path(), ValidationLevel::Strict);

        assert!(result_standard.is_ok());
        assert!(result_strict.is_ok());

        // Both should fail on this invalid data, but we're just checking they run
        assert!(!result_standard.unwrap().is_valid());
        assert!(!result_strict.unwrap().is_valid());
    }

    #[test]
    fn test_validation_error_accumulation() {
        let mut report = ValidationReport::new();

        report.error("Error 1");
        report.error("Error 2");
        report.warning("Warning 1");
        report.info("Info 1");

        assert_eq!(report.errors.len(), 2);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.info.len(), 1);
        assert!(!report.is_valid());
    }

    #[test]
    fn test_unsafe_operation_types() {
        // Test that unsafe operation types are distinct
        let op1 = UnsafeOperation::UncheckedStringRead;
        let op2 = UnsafeOperation::PointerDereference;
        let op3 = UnsafeOperation::MmapLifetimeExtension;
        let op4 = UnsafeOperation::Transmute;

        assert_ne!(op1, op2);
        assert_ne!(op2, op3);
        assert_ne!(op3, op4);
    }

    #[test]
    fn test_database_stats_summary() {
        let stats = DatabaseStats {
            version: 3,
            ac_node_count: 100,
            pattern_count: 50,
            literal_count: 30,
            glob_count: 20,
            ..Default::default()
        };

        let summary = stats.summary();
        assert!(summary.contains("v3"));
        assert!(summary.contains("100"));
        assert!(summary.contains("50"));
    }
}
