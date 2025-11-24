//! AC Literal ID Hash Table for O(1) Lookups
//!
//! This module provides a memory-mapped hash table for mapping AC literal IDs
//! to their associated pattern IDs. This enables O(1) database loading while
//! maintaining O(1) query performance.
//!
//! # Format
//!
//! The hash table is stored in a memory-mappable binary format:
//!
//! ```text
//! [Header]
//!   magic: [u8; 4]           // "ACLH"
//!   version: u32              // 1
//!   entry_count: u32          // Number of AC literals
//!   table_size: u32           // Hash table size (entry_count * 1.25)
//!   patterns_offset: u32      // Offset to pattern lists section
//!   patterns_size: u32        // Size of pattern lists section
//!
//! [Hash Table]
//!   entries: [HashEntry; table_size]
//!     literal_id: u32         // AC literal ID (or 0xFFFFFFFF if empty)
//!     patterns_offset: u32    // Offset into pattern lists section
//!     pattern_count: u32      // Number of patterns for this literal
//!     reserved: u32           // Reserved for alignment
//!
//! [Pattern Lists]
//!   For each literal: [pattern_id: u32, pattern_id: u32, ...]
//! ```

use crate::error::ParaglobError;
use rustc_hash::FxHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::mem;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref};

/// Magic bytes for AC literal hash section
pub const AC_LITERAL_HASH_MAGIC: &[u8; 4] = b"ACLH";

/// Current version of the AC literal hash format
pub const MATCHY_AC_LITERAL_HASH_VERSION: u32 = 1;

/// Empty slot marker
const EMPTY_SLOT: u32 = 0xFFFFFFFF;

/// Hash table header (24 bytes, 4-byte aligned)
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ACLiteralHashHeader {
    /// Magic bytes "ACLH"
    pub magic: [u8; 4],
    /// Format version
    pub version: u32,
    /// Number of AC literals
    pub entry_count: u32,
    /// Hash table size
    pub table_size: u32,
    /// Offset to pattern lists section
    pub patterns_offset: u32,
    /// Size of pattern lists section
    pub patterns_size: u32,
}

/// Single hash table entry (16 bytes, 4-byte aligned)
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ACHashEntry {
    /// AC literal ID (or EMPTY_SLOT if empty)
    pub literal_id: u32,
    /// Offset into pattern lists section
    pub patterns_offset: u32,
    /// Number of patterns for this literal
    pub pattern_count: u32,
    /// Reserved for alignment
    pub reserved: u32,
}

impl ACHashEntry {
    fn empty() -> Self {
        Self {
            literal_id: EMPTY_SLOT,
            patterns_offset: 0,
            pattern_count: 0,
            reserved: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.literal_id == EMPTY_SLOT
    }
}

/// Compute hash for a u32 literal ID
fn compute_hash(literal_id: u32) -> u64 {
    let mut hasher = FxHasher::default();
    literal_id.hash(&mut hasher);
    hasher.finish()
}

/// Builder for AC literal hash table
pub struct ACLiteralHashBuilder {
    // Map from AC literal ID to list of pattern IDs
    mappings: HashMap<u32, Vec<u32>>,
}

impl ACLiteralHashBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            mappings: HashMap::new(),
        }
    }

    /// Add a mapping from AC literal ID to pattern IDs
    pub fn add_mapping(&mut self, literal_id: u32, pattern_ids: Vec<u32>) {
        self.mappings.insert(literal_id, pattern_ids);
    }

    /// Build the hash table
    pub fn build(self) -> Result<Vec<u8>, ParaglobError> {
        if self.mappings.is_empty() {
            return Ok(Vec::new());
        }

        // Calculate table size (125% of entries for ~0.8 load factor)
        let table_size = (self.mappings.len() * 5).div_ceil(4).max(16);

        // Build pattern lists section
        let mut pattern_lists = Vec::new();
        let mut pattern_offsets = HashMap::new();

        for (literal_id, pattern_ids) in &self.mappings {
            pattern_offsets.insert(*literal_id, pattern_lists.len());
            for pattern_id in pattern_ids {
                pattern_lists.extend_from_slice(&pattern_id.to_le_bytes());
            }
        }

        // Build hash table with linear probing
        let mut table = vec![ACHashEntry::empty(); table_size];

        for (literal_id, pattern_ids) in &self.mappings {
            let hash = compute_hash(*literal_id);
            let mut slot = (hash as usize) % table_size;

            // Linear probing to find empty slot
            loop {
                if table[slot].is_empty() {
                    table[slot] = ACHashEntry {
                        literal_id: *literal_id,
                        patterns_offset: pattern_offsets[literal_id] as u32,
                        pattern_count: pattern_ids.len() as u32,
                        reserved: 0,
                    };
                    break;
                }
                slot = (slot + 1) % table_size;
            }
        }

        // Calculate offsets
        let header_size = mem::size_of::<ACLiteralHashHeader>();
        let table_bytes_size = table_size * mem::size_of::<ACHashEntry>();
        let patterns_offset = header_size + table_bytes_size;
        let patterns_size = pattern_lists.len();

        // Serialize everything
        let mut buffer = Vec::new();

        // Header
        let header = ACLiteralHashHeader {
            magic: *AC_LITERAL_HASH_MAGIC,
            version: MATCHY_AC_LITERAL_HASH_VERSION,
            entry_count: self.mappings.len() as u32,
            table_size: table_size as u32,
            patterns_offset: patterns_offset as u32,
            patterns_size: patterns_size as u32,
        };

        buffer.extend_from_slice(&header.magic);
        buffer.extend_from_slice(&header.version.to_le_bytes());
        buffer.extend_from_slice(&header.entry_count.to_le_bytes());
        buffer.extend_from_slice(&header.table_size.to_le_bytes());
        buffer.extend_from_slice(&header.patterns_offset.to_le_bytes());
        buffer.extend_from_slice(&header.patterns_size.to_le_bytes());

        // Hash table entries
        for entry in &table {
            buffer.extend_from_slice(&entry.literal_id.to_le_bytes());
            buffer.extend_from_slice(&entry.patterns_offset.to_le_bytes());
            buffer.extend_from_slice(&entry.pattern_count.to_le_bytes());
            buffer.extend_from_slice(&entry.reserved.to_le_bytes());
        }

        // Pattern lists
        buffer.extend_from_slice(&pattern_lists);

        Ok(buffer)
    }
}

impl Default for ACLiteralHashBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Memory-mapped AC literal hash table for lookups
#[derive(Clone)]
pub struct ACLiteralHash<'a> {
    buffer: &'a [u8],
    header: ACLiteralHashHeader,
    table_start: usize,
    patterns_start: usize,
}

impl<'a> ACLiteralHash<'a> {
    /// Load from memory-mapped buffer
    pub fn from_buffer(buffer: &'a [u8]) -> Result<Self, ParaglobError> {
        if buffer.len() < mem::size_of::<ACLiteralHashHeader>() {
            return Err(ParaglobError::InvalidPattern(
                "Buffer too small for AC literal hash header".to_string(),
            ));
        }

        // Parse header with zerocopy
        let (header_ref, _) = Ref::<_, ACLiteralHashHeader>::from_prefix(buffer).map_err(|_| {
            ParaglobError::InvalidPattern("Invalid AC literal hash header alignment".to_string())
        })?;
        let header = *header_ref;

        // Validate header
        if &header.magic != AC_LITERAL_HASH_MAGIC {
            return Err(ParaglobError::InvalidPattern(format!(
                "Invalid AC literal hash magic: expected {:?}, got {:?}",
                AC_LITERAL_HASH_MAGIC, header.magic
            )));
        }

        if header.version != MATCHY_AC_LITERAL_HASH_VERSION {
            return Err(ParaglobError::InvalidPattern(format!(
                "Unsupported AC literal hash version: {}",
                header.version
            )));
        }

        let table_start = mem::size_of::<ACLiteralHashHeader>();
        let patterns_start = header.patterns_offset as usize;

        Ok(Self {
            buffer,
            header,
            table_start,
            patterns_start,
        })
    }

    /// Lookup pattern IDs for an AC literal ID
    ///
    /// Returns the list of pattern IDs if found, None otherwise.
    /// This is O(1) average case with linear probing.
    pub fn lookup(&self, literal_id: u32) -> Option<Vec<u32>> {
        let hash = compute_hash(literal_id);
        let table_size = self.header.table_size as usize;
        let mut slot = (hash as usize) % table_size;

        let entry_size = mem::size_of::<ACHashEntry>();

        // Linear probing search
        for _ in 0..table_size {
            let entry_offset = self.table_start + slot * entry_size;
            if entry_offset + entry_size > self.buffer.len() {
                return None;
            }

            // Use zerocopy for entry parsing (HOT PATH optimization)
            let entry_slice = &self.buffer[entry_offset..];
            let (entry_ref, _) = Ref::<_, ACHashEntry>::from_prefix(entry_slice).ok()?;
            let entry = *entry_ref;

            // Empty slot - not found
            if entry.literal_id == EMPTY_SLOT {
                return None;
            }

            // Found it!
            if entry.literal_id == literal_id {
                return self.read_pattern_list(
                    entry.patterns_offset as usize,
                    entry.pattern_count as usize,
                );
            }

            slot = (slot + 1) % table_size;
        }

        None
    }

    /// Lookup and return pattern IDs as a slice (zero allocation)
    ///
    /// Returns a slice view into the buffer, or empty slice if not found.
    /// This is O(1) average case with linear probing.
    ///
    /// Note: Due to alignment requirements, this method now allocates a Vec.
    /// The zero-copy optimization was removed to ensure memory safety.
    pub fn lookup_slice(&self, literal_id: u32) -> Vec<u32> {
        self.lookup(literal_id).unwrap_or_default()
    }

    /// Read a pattern list from the patterns section
    fn read_pattern_list(&self, offset: usize, count: usize) -> Option<Vec<u32>> {
        let abs_offset = self.patterns_start + offset;
        let bytes_needed = count * 4; // u32 = 4 bytes

        if abs_offset + bytes_needed > self.buffer.len() {
            return None;
        }

        let mut patterns = Vec::with_capacity(count);
        for i in 0..count {
            let pattern_offset = abs_offset + i * 4;
            let pattern_id = u32::from_le_bytes(
                self.buffer[pattern_offset..pattern_offset + 4]
                    .try_into()
                    .ok()?,
            );
            patterns.push(pattern_id);
        }

        Some(patterns)
    }
}
