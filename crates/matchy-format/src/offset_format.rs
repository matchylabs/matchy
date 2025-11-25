//! Offset-based binary format for zero-copy memory mapping
//!
//! This module defines the **format-level** structures for matchy databases.
//! It orchestrates the overall .mxy file structure but delegates component-specific
//! details to their respective crates (matchy-paraglob, matchy-ip-trie, etc.).
//!
//! # Architectural Separation
//!
//! - **matchy-format**: Knows about section boundaries, offsets, and sizes
//! - **matchy-paraglob**: Owns its internal structures (AC nodes, patterns, etc.)
//! - **matchy-ip-trie**: Owns IP address trie structures
//! - **matchy-data-format**: Owns data encoding structures
//!
//! # Format Overview
//!
//! The format consists of C-compatible packed structs that can be cast directly
//! from bytes. All references use byte offsets from the start of the buffer.
//!
//! # High-Level Layout
//!
//! ```text
//! [ParaglobHeader (v5: 112 bytes)] - Points to all sections
//! [Paraglob section] - Internal structure owned by matchy-paraglob
//! [Data section: optional (v2+)] - Encoded by matchy-data-format
//! [Data mappings: PatternDataMapping array (v2+)]
//! [Glob Segments: GlobSegmentIndex + segment data (v5+)]
//! ```
//!
//! matchy-format only defines structures it directly reads/writes:
//! - `ParaglobHeader` - section pointers and sizes
//! - `PatternDataMapping` - maps patterns to data offsets
//! - `GlobSegmentIndex` / `GlobSegmentHeader` / `CharClassItemEncoded` - glob segment structures
//!
//! # Design Principles
//!
//! 1. **Alignment**: All structs are properly aligned for direct casting
//! 2. **Offsets**: All references use u32 byte offsets (4GB limit)
//! 3. **Zero-copy**: Can read directly from mmap without parsing
//! 4. **Portability**: Little-endian u32/u8 only (standard on x86/ARM)

use std::mem;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Magic bytes identifying Paraglob binary format
pub const MAGIC: &[u8; 8] = b"PARAGLOB";

/// Current format version (v5: serialized glob segments for zero-copy loading)
pub const MATCHY_FORMAT_VERSION: u32 = 5;

/// Previous format version (v4: uses ACNodeHot for 50% memory reduction)
#[allow(dead_code)]
pub const MATCHY_FORMAT_VERSION_V4: u32 = 4;

/// Previous format version (v3: adds AC literal mapping for zero-copy loading)
pub const MATCHY_FORMAT_VERSION_V3: u32 = 3;

/// Previous format version (v2: adds data section support)
pub const MATCHY_FORMAT_VERSION_V2: u32 = 2;

/// Previous format version (v1: patterns only, no data)
pub const MATCHY_FORMAT_VERSION_V1: u32 = 1;

/// Main header for serialized Paraglob database (112 bytes, 4-byte aligned)
///
/// This header appears at the start of every serialized Paraglob file.
/// All offsets are relative to the start of the buffer.
///
/// # Version History
/// - v1 (72 bytes): Original format, patterns only
/// - v2 (96 bytes): Adds data section support for pattern-associated data
/// - v3 (104 bytes): Adds AC literal mapping for O(1) zero-copy loading
/// - v4 (104 bytes): Uses ACNodeHot (20-byte) instead of ACNode (32-byte) - BREAKING
/// - v5 (112 bytes): Adds serialized glob segments for zero-copy loading
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ParaglobHeader {
    /// Magic bytes: "PARAGLOB"
    pub magic: [u8; 8],

    /// Format version (currently 5)
    pub version: u32,

    /// Match mode: 0=CaseSensitive, 1=CaseInsensitive
    pub match_mode: u32,

    // AC Automaton section
    /// Number of nodes in the AC trie
    pub ac_node_count: u32,

    /// Offset to first AC node
    pub ac_nodes_offset: u32,

    /// Total size of AC edges data
    pub ac_edges_size: u32,

    /// Total size of AC pattern ID arrays
    pub ac_patterns_size: u32,

    // Pattern section
    /// Total number of original glob patterns
    pub pattern_count: u32,

    /// Offset to pattern entry array
    pub patterns_offset: u32,

    /// Offset to pattern strings area
    pub pattern_strings_offset: u32,

    /// Total size of pattern strings
    pub pattern_strings_size: u32,

    // Meta-word mapping section
    /// Number of meta-word to pattern mappings
    pub meta_word_mapping_count: u32,

    /// Offset to meta-word mapping array
    pub meta_word_mappings_offset: u32,

    /// Total size of pattern reference arrays
    pub pattern_refs_size: u32,

    /// Number of pure wildcard patterns (no literals)
    pub wildcard_count: u32,

    /// Total size of the entire serialized buffer (bytes)
    pub total_buffer_size: u32,

    /// Endianness marker: 0x01=little-endian, 0x02=big-endian, 0x00=legacy (assume little-endian)
    /// Database is always stored in little-endian format.
    /// This field indicates the endianness of the system that created the file.
    /// On big-endian systems, all multi-byte values are byte-swapped on read.
    pub endianness: u8,

    /// Reserved for future use
    pub reserved: [u8; 3],

    // ===== v2 ADDITIONS (24 bytes) =====
    /// Offset to data section (0 = no data section)
    /// Points to MMDB-encoded data or other serialized data
    pub data_section_offset: u32,

    /// Size of data section in bytes (0 = no data)
    pub data_section_size: u32,

    /// Offset to pattern→data mapping table (0 = no mappings)
    /// Each mapping is a PatternDataMapping struct
    pub mapping_table_offset: u32,

    /// Number of pattern→data mappings
    /// Should equal pattern_count if all patterns have data
    pub mapping_count: u32,

    /// Data type flags:
    /// - Bit 0: inline data (1) vs external references (0)
    /// - Bit 1-31: reserved
    pub data_flags: u32,

    /// Reserved for future v2+ features
    pub reserved_v2: u32,

    // ===== v3 ADDITIONS (8 bytes) =====
    /// Offset to AC literal→pattern mapping table (0 = no mapping, requires reconstruction)
    /// Points to serialized `HashMap<u32, Vec<u32>>` for instant loading
    /// Format: `[entry_count: u32]` followed by entries of:
    ///   `[literal_id: u32][pattern_count: u32][pattern_id: u32, ...]`
    pub ac_literal_map_offset: u32,

    /// Number of entries in AC literal mapping table
    /// 0 = v1/v2 file, requires reconstruct_literal_mapping()
    pub ac_literal_map_count: u32,

    // ===== v5 ADDITIONS (8 bytes) =====
    /// Offset to glob segment index (0 = no segments, use lazy parsing)
    /// Points to array of GlobSegmentIndex structs (one per pattern)
    pub glob_segments_offset: u32,

    /// Total size of glob segment data (index + segment structures + string data)
    pub glob_segments_size: u32,
}


/// Pattern-to-data mapping entry (12 bytes, 4-byte aligned)
///
/// Maps a pattern ID to associated data. Used in v2 format.
/// The data can be inline (stored in data section) or external
/// (reference to MMDB data section).
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct PatternDataMapping {
    /// Pattern ID this mapping applies to
    pub pattern_id: u32,

    /// Offset to data in data section (or external offset)
    /// Interpretation depends on data_flags in header
    pub data_offset: u32,

    /// Size of data in bytes (0 = use data section's size encoding)
    pub data_size: u32,
}

/// Glob segment index entry (8 bytes, 4-byte aligned)
///
/// Points to the glob segment data for a specific pattern.
/// One entry exists for each pattern in the database.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct GlobSegmentIndex {
    /// Offset to first GlobSegmentHeader for this pattern
    /// Relative to start of buffer
    pub first_segment_offset: u32,

    /// Number of segments in this pattern
    pub segment_count: u16,

    /// Reserved for alignment
    pub reserved: u16,
}

/// Glob segment header (12 bytes, 4-byte aligned)
///
/// Describes a single segment of a glob pattern (Literal, Star, Question, or CharClass).
/// Followed immediately by segment-specific data (string bytes or CharClassItem array).
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct GlobSegmentHeader {
    /// Segment type:
    /// - 0: Literal(String)
    /// - 1: Star
    /// - 2: Question
    /// - 3: CharClass
    pub segment_type: u8,

    /// Flags (for CharClass: bit 0 = negated)
    pub flags: u8,

    /// Reserved for alignment
    pub reserved: u16,

    /// Length of associated data in bytes
    /// - Literal: string byte length
    /// - Star/Question: 0
    /// - CharClass: number of CharClassItem entries * 12
    pub data_len: u32,

    /// Offset to associated data (relative to start of buffer)
    /// - Literal: offset to UTF-8 string bytes
    /// - Star/Question: unused (0)
    /// - CharClass: offset to CharClassItemEncoded array
    pub data_offset: u32,
}

/// Encoded character class item (12 bytes, 4-byte aligned)
///
/// Represents either a single character or a character range in a glob character class.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct CharClassItemEncoded {
    /// Item type:
    /// - 0: Char(char1)
    /// - 1: Range(char1, char2)
    pub item_type: u8,

    /// Reserved for alignment
    pub reserved: [u8; 3],

    /// First character (or only character for Char variant)
    pub char1: u32,

    /// Second character (for Range variant only, 0 for Char)
    pub char2: u32,
}

// Compile-time size assertions to ensure struct layout
const _: () = assert!(mem::size_of::<ParaglobHeader>() == 112); // v5: 8-byte magic + 26 * u32 fields
const _: () = assert!(mem::size_of::<PatternDataMapping>() == 12);
const _: () = assert!(mem::size_of::<GlobSegmentIndex>() == 8);
const _: () = assert!(mem::size_of::<GlobSegmentHeader>() == 12);
const _: () = assert!(mem::size_of::<CharClassItemEncoded>() == 12);

impl Default for ParaglobHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl PatternDataMapping {
    /// Create a new pattern-to-data mapping
    pub fn new(pattern_id: u32, data_offset: u32, data_size: u32) -> Self {
        Self {
            pattern_id,
            data_offset,
            data_size,
        }
    }
}

impl ParaglobHeader {
    /// Create a new v3 header with magic and version
    pub fn new() -> Self {
        Self {
            magic: *MAGIC,
            version: MATCHY_FORMAT_VERSION,
            match_mode: 0,
            ac_node_count: 0,
            ac_nodes_offset: 0,
            ac_edges_size: 0,
            ac_patterns_size: 0,
            pattern_count: 0,
            patterns_offset: 0,
            pattern_strings_offset: 0,
            pattern_strings_size: 0,
            meta_word_mapping_count: 0,
            meta_word_mappings_offset: 0,
            pattern_refs_size: 0,
            wildcard_count: 0,
            total_buffer_size: 0,
            endianness: 0x01, // Little-endian marker (reserved for future use)
            reserved: [0; 3],
            // v2 fields
            data_section_offset: 0,
            data_section_size: 0,
            mapping_table_offset: 0,
            mapping_count: 0,
            data_flags: 0,
            reserved_v2: 0,
            // v3 fields
            ac_literal_map_offset: 0,
            ac_literal_map_count: 0,
            // v5 fields
            glob_segments_offset: 0,
            glob_segments_size: 0,
        }
    }

    /// Validate header magic and version
    pub fn validate(&self) -> Result<(), &'static str> {
        if &self.magic != MAGIC {
            return Err("Invalid magic bytes");
        }
        if self.version != MATCHY_FORMAT_VERSION {
            return Err("Unsupported version - only v5 format supported");
        }
        Ok(())
    }

    /// Validate that all header offsets are within buffer bounds
    pub fn validate_offsets(&self, buffer_len: usize) -> Result<(), &'static str> {
        // Validate AC literal mapping offset if present
        if self.has_ac_literal_mapping() {
            let offset = self.ac_literal_map_offset as usize;
            if offset >= buffer_len {
                return Err("AC literal map offset out of bounds");
            }
        }

        // Validate data section if present
        if self.has_data_section() {
            let start = self.data_section_offset as usize;
            let size = self.data_section_size as usize;
            if start.checked_add(size).is_none_or(|end| end > buffer_len) {
                return Err("Data section out of bounds");
            }
        }

        // Validate mapping table if present
        if self.mapping_count > 0 {
            let offset = self.mapping_table_offset as usize;
            if offset >= buffer_len {
                return Err("Mapping table offset out of bounds");
            }
        }

        // NOTE: Paraglob section validates its own internal structures.
        // matchy-format only validates format-level concerns (data sections, mappings).
        // AC nodes, patterns, meta-words are all paraglob implementation details.

        Ok(())
    }

    /// Check if this file has a data section
    pub fn has_data_section(&self) -> bool {
        self.data_section_size > 0
    }

    /// Check if this file has a pre-built AC literal mapping (v3+)
    pub fn has_ac_literal_mapping(&self) -> bool {
        self.ac_literal_map_count > 0 && self.ac_literal_map_offset > 0
    }

    /// Check if data is inline (true) or external references (false)
    pub fn has_inline_data(&self) -> bool {
        (self.data_flags & 0x1) != 0
    }

    /// Check if this file has pre-built glob segments (v5+)
    pub fn has_glob_segments(&self) -> bool {
        self.glob_segments_size > 0 && self.glob_segments_offset > 0
    }
}


/// Helper to safely read a struct from a byte buffer at an offset
///
/// # Safety
///
/// Caller must ensure:
/// - offset + `size_of::<T>`() <= buffer.len()
/// - Buffer is properly aligned for T
/// - Bytes represent a valid T
#[allow(dead_code)]
pub unsafe fn read_struct<T: Copy>(buffer: &[u8], offset: usize) -> T {
    debug_assert!(offset + mem::size_of::<T>() <= buffer.len());
    let ptr = buffer.as_ptr().add(offset) as *const T;
    ptr.read_unaligned()
}

/// Helper to safely read a slice of structs from a byte buffer
///
/// # Safety
///
/// Caller must ensure:
/// - offset + `size_of::<T>`() * count <= buffer.len()
/// - Buffer contains valid T values
#[allow(dead_code)]
pub unsafe fn read_struct_slice<T: Copy>(buffer: &[u8], offset: usize, count: usize) -> &[T] {
    debug_assert!(offset + mem::size_of::<T>() * count <= buffer.len());
    let ptr = buffer.as_ptr().add(offset) as *const T;
    std::slice::from_raw_parts(ptr, count)
}

/// Helper to read a null-terminated UTF-8 string from buffer
///
/// # Safety
///
/// Caller must ensure:
/// - offset < buffer.len()
/// - String is null-terminated
/// - Bytes are valid UTF-8
pub unsafe fn read_cstring(buffer: &[u8], offset: usize) -> Result<&str, &'static str> {
    if offset >= buffer.len() {
        return Err("Offset out of bounds");
    }

    // Find null terminator
    let start = offset;
    let mut end = offset;
    while end < buffer.len() && buffer[end] != 0 {
        end += 1;
    }

    if end >= buffer.len() {
        return Err("String not null-terminated");
    }

    // Convert to str
    std::str::from_utf8(&buffer[start..end]).map_err(|_| "Invalid UTF-8")
}

/// Helper to read a UTF-8 string from buffer with known length (FAST PATH)
///
/// This is much faster than `read_cstring` because it doesn't scan for the null terminator.
/// Use this when you have the string length from PatternEntry.pattern_string_length.
///
/// # Safety
///
/// Caller must ensure:
/// - offset + length <= buffer.len()
/// - Bytes are valid UTF-8
/// - Length is correct
#[inline]
#[allow(dead_code)]
pub unsafe fn read_cstring_with_len(
    buffer: &[u8],
    offset: usize,
    length: usize,
) -> Result<&str, &'static str> {
    if offset + length > buffer.len() {
        return Err("Offset + length out of bounds");
    }

    // Direct slice without scanning for null terminator
    std::str::from_utf8(&buffer[offset..offset + length]).map_err(|_| "Invalid UTF-8")
}

/// Helper to read a UTF-8 string from buffer with known length (ULTRA-FAST PATH - NO UTF-8 VALIDATION)
///
/// This is the fastest option - it skips null terminator scanning AND UTF-8 validation.
/// Only use this in hot query paths where you KNOW the strings are valid UTF-8 (from build time).
///
/// # Safety
///
/// Caller must ensure:
/// - offset + length <= buffer.len()
/// - Bytes are DEFINITELY valid UTF-8 (undefined behavior if not!)
/// - Length is correct
#[inline]
#[allow(dead_code)]
pub unsafe fn read_str_unchecked(buffer: &[u8], offset: usize, length: usize) -> &str {
    debug_assert!(offset + length <= buffer.len());
    // SAFETY: Caller guarantees valid UTF-8
    std::str::from_utf8_unchecked(&buffer[offset..offset + length])
}

/// Helper to read a UTF-8 string from buffer with known length (SAFE PATH - validates UTF-8)
///
/// This validates UTF-8 on every read. Use for untrusted databases.
/// Slower than `read_str_unchecked` but prevents undefined behavior.
///
/// # Safety
///
/// Caller must ensure:
/// - offset + length <= buffer.len()
/// - Length is correct
///
/// UTF-8 validation is performed, so invalid UTF-8 returns an error.
#[inline]
#[allow(dead_code)]
pub unsafe fn read_str_checked(
    buffer: &[u8],
    offset: usize,
    length: usize,
) -> Result<&str, &'static str> {
    if offset + length > buffer.len() {
        return Err("Offset + length out of bounds");
    }
    std::str::from_utf8(&buffer[offset..offset + length]).map_err(|_| "Invalid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_size() {
        assert_eq!(mem::size_of::<ParaglobHeader>(), 112); // v5: 8-byte magic + 26 * u32
        assert_eq!(mem::align_of::<ParaglobHeader>(), 4);
    }

    #[test]
    fn test_header_validation() {
        let mut header = ParaglobHeader::new();
        assert!(header.validate().is_ok());
        assert_eq!(header.version, MATCHY_FORMAT_VERSION);

        header.magic = *b"INVALID!";
        assert!(header.validate().is_err());

        header.magic = *MAGIC;
        header.version = 999;
        assert!(header.validate().is_err());

        // Only v4 is valid
        header.version = MATCHY_FORMAT_VERSION_V1;
        assert!(header.validate().is_err());

        header.version = MATCHY_FORMAT_VERSION_V2;
        assert!(header.validate().is_err());

        header.version = MATCHY_FORMAT_VERSION_V3;
        assert!(header.validate().is_err());

        header.version = MATCHY_FORMAT_VERSION;
        assert!(header.validate().is_ok());
    }

    #[test]
    fn test_v3_features() {
        let mut header = ParaglobHeader::new();
        assert_eq!(header.version, MATCHY_FORMAT_VERSION);
        assert!(!header.has_data_section());
        assert!(!header.has_inline_data());
        assert!(!header.has_ac_literal_mapping());

        // Add data section
        header.data_section_size = 1024;
        assert!(header.has_data_section());

        // Set inline data flag
        header.data_flags = 0x1;
        assert!(header.has_inline_data());

        // Add AC literal mapping
        header.ac_literal_map_offset = 1000;
        header.ac_literal_map_count = 50;
        assert!(header.has_ac_literal_mapping());
    }

    #[test]
    fn test_read_struct() {
        let mut buffer = vec![0u8; 112]; // v5 header size
        let header = ParaglobHeader::new();

        // Write header to buffer
        unsafe {
            let ptr = buffer.as_mut_ptr() as *mut ParaglobHeader;
            ptr.write(header);
        }

        // Read it back
        let read_header: ParaglobHeader = unsafe { read_struct(&buffer, 0) };
        assert_eq!(read_header.magic, *MAGIC);
        assert_eq!(read_header.version, MATCHY_FORMAT_VERSION);
        assert_eq!(read_header.version, 5);
    }

    #[test]
    fn test_read_cstring() {
        let buffer = b"hello\0world\0\0";

        unsafe {
            let s1 = read_cstring(buffer, 0).unwrap();
            assert_eq!(s1, "hello");

            let s2 = read_cstring(buffer, 6).unwrap();
            assert_eq!(s2, "world");

            let s3 = read_cstring(buffer, 12).unwrap();
            assert_eq!(s3, "");
        }
    }
}
