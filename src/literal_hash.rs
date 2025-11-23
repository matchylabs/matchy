//! Literal String Hash Table for O(1) Lookups
//!
//! This module provides a memory-mapped hash table optimized for exact string matching.
//! Unlike Aho-Corasick which is designed for pattern matching, this provides O(1) lookups
//! for literal strings using XXH64 with sharded parallel construction.
//!
//! # Format
//!
//! The hash table is stored in a memory-mappable binary format:
//!
//! ```text
//! [Header]
//!   magic: [u8; 4]           // "LHSH"
//!   version: u32              // 1
//!   entry_count: u32          // Number of literal patterns
//!   table_size: u32           // Hash table size (entry_count * 1.25)
//!   strings_offset: u32       // Offset to string pool
//!   strings_size: u32         // Size of string pool
//!   num_shards: u32           // Number of shards (power of 2)
//!   shard_bits: u32           // Bits used for sharding (log2(num_shards))
//!
//! [Hash Table]
//!   Sharded table: [Shard0][Shard1]...[ShardN]
//!   Each shard is a power-of-two sized slice
//!   entries: [HashEntry; table_size]
//!     hash: u64               // Full hash for verification
//!     string_offset: u32      // Offset into string pool (or 0xFFFFFFFF if empty)
//!     pattern_id: u32         // Pattern ID for data lookup
//!
//! [String Pool]
//!   Concatenated shard string pools
//!   Strings stored as: [length: u16][bytes...][null terminator]
//!
//! [Pattern Mappings]
//!   count: u32
//!   mappings: [(pattern_id: u32, data_offset: u32); count]
//! ```
//!
use crate::error::ParaglobError;
use crate::glob::MatchMode;
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::mem;
use xxhash_rust::xxh64::xxh64;

/// Magic bytes for literal hash section
pub const LITERAL_HASH_MAGIC: &[u8; 4] = b"LHSH";

/// Current version of the literal hash format
pub const MATCHY_LITERAL_HASH_VERSION: u32 = 1;

/// Empty slot marker
const EMPTY_SLOT: u32 = 0xFFFFFFFF;

/// Hash table header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LiteralHashHeader {
    /// Magic bytes "LHSH"
    pub magic: [u8; 4],
    /// Format version
    pub version: u32,
    /// Number of literal patterns
    pub entry_count: u32,
    /// Hash table size
    pub table_size: u32,
    /// Offset to string pool
    pub strings_offset: u32,
    /// Size of string pool
    pub strings_size: u32,
    /// Number of shards (power of 2)
    pub num_shards: u32,
    /// Bits used for sharding (log2(num_shards))
    pub shard_bits: u32,
}

/// Single hash table entry
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HashEntry {
    /// Full hash for verification
    pub hash: u64,
    /// Offset into string pool
    pub string_offset: u32,
    /// Pattern ID for data lookup
    pub pattern_id: u32,
}

impl HashEntry {
    fn empty() -> Self {
        Self {
            hash: 0,
            string_offset: EMPTY_SLOT,
            pattern_id: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.string_offset == EMPTY_SLOT
    }
}

/// Pattern ID to data offset mapping
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PatternMapping {
    /// Pattern identifier
    pub pattern_id: u32,
    /// Offset to data section
    pub data_offset: u32,
}

/// Single shard of the hash table
struct Shard {
    table: Vec<HashEntry>,
    strings: Vec<u8>,
    shard_id: usize,
}

/// Builder for literal hash table
pub struct LiteralHashBuilder {
    patterns: Vec<(String, u32, u64)>, // (pattern, pattern_id, hash)
    mode: MatchMode,
}

impl LiteralHashBuilder {
    /// Create a new builder
    pub fn new(mode: MatchMode) -> Self {
        Self {
            patterns: Vec::new(),
            mode,
        }
    }

    /// Add a literal pattern
    pub fn add_pattern(&mut self, pattern: &str, pattern_id: u32) {
        // Normalize pattern based on match mode and pre-compute hash
        let normalized = match self.mode {
            MatchMode::CaseSensitive => pattern.to_string(),
            MatchMode::CaseInsensitive => pattern.to_lowercase(),
        };
        let hash = compute_hash(&normalized);
        self.patterns.push((normalized, pattern_id, hash));
    }

    /// Build the hash table with parallel sharding
    ///
    /// Returns (hash_table_bytes, pattern_id_to_data_offset_map)
    pub fn build(
        self,
        pattern_data_offsets: &[(u32, u32)], // (pattern_id, data_offset)
    ) -> Result<Vec<u8>, ParaglobError> {
        if self.patterns.is_empty() {
            return Ok(Vec::new());
        }

        let start = std::time::Instant::now();
        eprintln!(
            "[LiteralHash] Building hash table for {} patterns...",
            self.patterns.len()
        );

        // Determine number of shards adaptively based on dataset size
        // Small datasets: fewer shards to avoid memory overhead
        // Large datasets: more shards for parallelism
        let shard_bits = if self.patterns.len() < 10_000 {
            4 // 16 shards for small datasets
        } else if self.patterns.len() < 100_000 {
            5 // 32 shards for medium datasets
        } else {
            6 // 64 shards for large datasets
        };
        let num_shards = 1 << shard_bits;
        eprintln!(
            "[LiteralHash] Using {} shards for {} patterns",
            num_shards,
            self.patterns.len()
        );

        // We'll calculate per-shard capacity during build (after partitioning)
        // to avoid allocating huge empty tables
        eprintln!("[LiteralHash] Partitioning will determine per-shard sizes...");

        // Partition entries into shards by top shard_bits of hash
        eprintln!("[LiteralHash] Partitioning into shards...");
        let mut shard_buckets: Vec<Vec<(String, u32, u64)>> =
            (0..num_shards).map(|_| Vec::new()).collect();

        for (pattern, pattern_id, hash) in self.patterns {
            // Better distribution: use modulo instead of top bits
            let shard_id = (hash as usize) % num_shards;
            shard_buckets[shard_id].push((pattern, pattern_id, hash));
        }
        eprintln!(
            "[LiteralHash] Partitioned into shards ({:?})",
            start.elapsed()
        );

        // Build shards in batches to limit memory usage
        // Batch size scales with available parallelism (respects RAYON_NUM_THREADS)
        let parallelism = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(8);
        let batch_size = parallelism.min(num_shards).max(1);
        eprintln!(
            "[LiteralHash] Building shards in batches ({} at a time, {} cores available)...",
            batch_size, parallelism
        );
        let mut shards = Vec::with_capacity(num_shards);

        for chunk_start in (0..num_shards).step_by(batch_size) {
            let chunk_end = (chunk_start + batch_size).min(num_shards);
            eprintln!("[LiteralHash]   Batch {}-{}...", chunk_start, chunk_end - 1);

            let mut chunk: Vec<Shard> = shard_buckets[chunk_start..chunk_end]
                .par_iter_mut()
                .enumerate()
                .map(|(i, entries)| {
                    let shard_id = chunk_start + i;
                    let entries_vec = std::mem::take(entries); // Move data, free memory
                    build_shard_auto_size(shard_id, entries_vec)
                })
                .collect();

            shards.append(&mut chunk);
        }

        eprintln!("[LiteralHash] All shards built ({:?})", start.elapsed());

        // Concatenate shards into final table and string pool
        eprintln!("[LiteralHash] Concatenating shards...");
        let table_size: usize = shards.iter().map(|s| s.table.len()).sum();
        let mut final_table = Vec::with_capacity(table_size);
        let mut final_string_pool = Vec::new();
        let mut pool_offset = 0;

        // Build shard offset table for lookups
        let mut shard_offsets = vec![0u32; num_shards + 1]; // +1 for end sentinel
        let mut table_offset = 0u32;

        for shard in &shards {
            shard_offsets[shard.shard_id] = table_offset;
            table_offset += shard.table.len() as u32;
        }
        shard_offsets[num_shards] = table_offset; // End sentinel

        for mut shard in shards {
            let shard_pool_size = shard.strings.len() as u32;

            // Adjust string offsets by pool base
            for entry in &mut shard.table {
                if !entry.is_empty() {
                    entry.string_offset += pool_offset;
                }
            }

            final_table.extend(shard.table);
            final_string_pool.extend(shard.strings);
            pool_offset += shard_pool_size;
        }
        eprintln!("[LiteralHash] Shards concatenated ({:?})", start.elapsed());

        // Calculate offsets
        let header_size = 32; // Fixed: 4 bytes magic + 7 u32 fields
        let shard_table_size = (num_shards + 1) * 4; // Shard offset table
        let table_bytes_size = table_size * mem::size_of::<HashEntry>();
        let strings_offset = header_size + shard_table_size + table_bytes_size;
        let strings_size = final_string_pool.len();

        // Pre-allocate entire buffer to avoid reallocation
        let total_size = header_size
            + table_bytes_size
            + strings_size
            + 4 // pattern_data_offsets count
            + (pattern_data_offsets.len() * 8); // pattern mappings
        let mut buffer = Vec::with_capacity(total_size);

        // Header
        let entry_count = final_table.iter().filter(|e| !e.is_empty()).count();
        let header = LiteralHashHeader {
            magic: *LITERAL_HASH_MAGIC,
            version: MATCHY_LITERAL_HASH_VERSION,
            entry_count: entry_count as u32,
            table_size: table_size as u32,
            strings_offset: strings_offset as u32,
            strings_size: strings_size as u32,
            num_shards: num_shards as u32,
            shard_bits,
        };

        buffer.extend_from_slice(&header.magic);
        buffer.extend_from_slice(&header.version.to_le_bytes());
        buffer.extend_from_slice(&header.entry_count.to_le_bytes());
        buffer.extend_from_slice(&header.table_size.to_le_bytes());
        buffer.extend_from_slice(&header.strings_offset.to_le_bytes());
        buffer.extend_from_slice(&header.strings_size.to_le_bytes());
        buffer.extend_from_slice(&header.num_shards.to_le_bytes());
        buffer.extend_from_slice(&header.shard_bits.to_le_bytes());

        // Write shard offset table
        for offset in &shard_offsets {
            buffer.extend_from_slice(&offset.to_le_bytes());
        }

        // Hash table entries - write in bulk with unsafe for performance
        let entry_size = mem::size_of::<HashEntry>();
        let table_start = buffer.len();
        unsafe {
            buffer.reserve(table_bytes_size);
            let ptr = buffer.as_mut_ptr().add(table_start);

            for (i, entry) in final_table.iter().enumerate() {
                let entry_ptr = ptr.add(i * entry_size) as *mut HashEntry;
                std::ptr::write(
                    entry_ptr,
                    HashEntry {
                        hash: entry.hash,
                        string_offset: entry.string_offset,
                        pattern_id: entry.pattern_id,
                    },
                );
            }

            buffer.set_len(table_start + table_bytes_size);
        }

        // String pool
        buffer.extend_from_slice(&final_string_pool);

        // Pattern mappings - write in bulk
        buffer.extend_from_slice(&(pattern_data_offsets.len() as u32).to_le_bytes());
        unsafe {
            let mappings_start = buffer.len();
            let mappings_size = pattern_data_offsets.len() * 8; // 2 u32s per mapping
            buffer.reserve(mappings_size);
            let ptr = buffer.as_mut_ptr().add(mappings_start);

            for (i, (pattern_id, data_offset)) in pattern_data_offsets.iter().enumerate() {
                let offset = i * 8;
                std::ptr::copy_nonoverlapping(
                    pattern_id.to_le_bytes().as_ptr(),
                    ptr.add(offset),
                    4,
                );
                std::ptr::copy_nonoverlapping(
                    data_offset.to_le_bytes().as_ptr(),
                    ptr.add(offset + 4),
                    4,
                );
            }

            buffer.set_len(mappings_start + mappings_size);
        }

        eprintln!("[LiteralHash] Total build time: {:?}", start.elapsed());
        Ok(buffer)
    }

    /// Get number of patterns
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

impl Default for LiteralHashBuilder {
    fn default() -> Self {
        Self::new(MatchMode::CaseSensitive)
    }
}

/// Memory-mapped literal hash table for lookups
#[derive(Clone)]
pub struct LiteralHash<'a> {
    buffer: &'a [u8],
    header: LiteralHashHeader,
    table_start: usize,
    strings_start: usize,
    mappings_start: usize,
    shard_offsets: Vec<u32>, // Offset of each shard in the table
    mode: MatchMode,
}

impl<'a> LiteralHash<'a> {
    /// Load from memory-mapped buffer
    pub fn from_buffer(buffer: &'a [u8], mode: MatchMode) -> Result<Self, ParaglobError> {
        // Header size: 4 + 7*4 = 32 bytes (magic + 7 u32 fields)
        const HEADER_SIZE: usize = 32;
        if buffer.len() < HEADER_SIZE {
            return Err(ParaglobError::InvalidPattern(
                "Buffer too small for literal hash header".to_string(),
            ));
        }

        // Parse header
        let magic = &buffer[0..4];
        if magic != LITERAL_HASH_MAGIC {
            return Err(ParaglobError::InvalidPattern(format!(
                "Invalid literal hash magic: expected {:?}, got {:?}",
                LITERAL_HASH_MAGIC, magic
            )));
        }

        let version = u32::from_le_bytes(buffer[4..8].try_into().unwrap());
        if version != MATCHY_LITERAL_HASH_VERSION {
            return Err(ParaglobError::InvalidPattern(format!(
                "Unsupported literal hash version: {}",
                version
            )));
        }

        let entry_count = u32::from_le_bytes(buffer[8..12].try_into().unwrap());
        let table_size = u32::from_le_bytes(buffer[12..16].try_into().unwrap());
        let strings_offset = u32::from_le_bytes(buffer[16..20].try_into().unwrap());
        let strings_size = u32::from_le_bytes(buffer[20..24].try_into().unwrap());
        let num_shards = u32::from_le_bytes(buffer[24..28].try_into().unwrap());
        let shard_bits = u32::from_le_bytes(buffer[28..32].try_into().unwrap());

        let header = LiteralHashHeader {
            magic: *LITERAL_HASH_MAGIC,
            version,
            entry_count,
            table_size,
            strings_offset,
            strings_size,
            num_shards,
            shard_bits,
        };

        // Header is 32 bytes: 4 byte magic + 7 u32 fields
        let header_size = 32;

        // Read shard offset table (num_shards + 1 entries)
        let shard_table_start = header_size;
        let shard_table_size = (num_shards as usize + 1) * 4;
        let mut shard_offsets = Vec::with_capacity(num_shards as usize + 1);
        for i in 0..=num_shards as usize {
            let offset_pos = shard_table_start + i * 4;
            if offset_pos + 4 > buffer.len() {
                return Err(ParaglobError::InvalidPattern(
                    "Shard offset table truncated".to_string(),
                ));
            }
            let offset = u32::from_le_bytes(buffer[offset_pos..offset_pos + 4].try_into().unwrap());
            shard_offsets.push(offset);
        }

        let table_start = shard_table_start + shard_table_size;
        let strings_start = strings_offset as usize;
        let mappings_start = strings_start + strings_size as usize;

        Ok(Self {
            buffer,
            header,
            table_start,
            strings_start,
            mappings_start,
            shard_offsets,
            mode,
        })
    }

    /// Get the match mode of this literal hash table
    pub fn mode(&self) -> MatchMode {
        self.mode
    }

    /// Lookup a literal string using sharded table
    ///
    /// Returns the pattern ID if found, None otherwise
    pub fn lookup(&self, query: &str) -> Option<u32> {
        // Normalize query based on match mode
        let normalized_query = match self.mode {
            MatchMode::CaseSensitive => query.to_string(),
            MatchMode::CaseInsensitive => query.to_lowercase(),
        };
        let hash = compute_hash(&normalized_query);

        // Compute shard and shard bounds using offset table
        let num_shards = self.header.num_shards as usize;
        let shard_id = (hash as usize) % num_shards;

        let shard_start = self.shard_offsets[shard_id] as usize;
        let shard_end = self.shard_offsets[shard_id + 1] as usize;
        let shard_capacity = shard_end - shard_start;

        if shard_capacity == 0 {
            return None; // Empty shard
        }

        // Shard capacity is always power of 2, so mask works
        let shard_mask = shard_capacity - 1;

        let base_slot = (hash as usize) & shard_mask; // Position within shard
        let mut slot = shard_start + base_slot; // Absolute position
        let entry_size = mem::size_of::<HashEntry>();

        // Lookup within shard only
        for _ in 0..shard_capacity {
            let entry_offset = self.table_start + slot * entry_size;
            if entry_offset + entry_size > self.buffer.len() {
                return None;
            }

            let entry_bytes = &self.buffer[entry_offset..entry_offset + entry_size];
            let entry_hash = u64::from_le_bytes(entry_bytes[0..8].try_into().unwrap());
            let string_offset = u32::from_le_bytes(entry_bytes[8..12].try_into().unwrap());
            let pattern_id = u32::from_le_bytes(entry_bytes[12..16].try_into().unwrap());

            // Empty slot - not found
            if string_offset == EMPTY_SLOT {
                return None;
            }

            // Hash matches - verify string
            if entry_hash == hash {
                if let Some(stored_string) = self.read_string(string_offset as usize) {
                    if stored_string == normalized_query {
                        return Some(pattern_id);
                    }
                }
            }

            // Wrap within shard only
            slot = shard_start + ((slot + 1 - shard_start) & shard_mask);
        }

        None
    }

    /// Read a string from the string pool
    fn read_string(&self, offset: usize) -> Option<&str> {
        let abs_offset = self.strings_start + offset;
        if abs_offset + 2 > self.buffer.len() {
            return None;
        }

        let len = u16::from_le_bytes(self.buffer[abs_offset..abs_offset + 2].try_into().ok()?);
        let str_start = abs_offset + 2;
        let str_end = str_start + len as usize;

        if str_end > self.buffer.len() {
            return None;
        }

        std::str::from_utf8(&self.buffer[str_start..str_end]).ok()
    }

    /// Get data offset for a pattern ID
    pub fn get_data_offset(&self, pattern_id: u32) -> Option<u32> {
        if self.mappings_start + 4 > self.buffer.len() {
            return None;
        }

        let count = u32::from_le_bytes(
            self.buffer[self.mappings_start..self.mappings_start + 4]
                .try_into()
                .ok()?,
        );

        let mappings_data_start = self.mappings_start + 4;
        let mapping_size = 8; // pattern_id: u32 + data_offset: u32

        for i in 0..count {
            let offset = mappings_data_start + (i as usize) * mapping_size;
            if offset + mapping_size > self.buffer.len() {
                return None;
            }

            let pid = u32::from_le_bytes(self.buffer[offset..offset + 4].try_into().ok()?);
            if pid == pattern_id {
                let data_offset =
                    u32::from_le_bytes(self.buffer[offset + 4..offset + 8].try_into().ok()?);
                return Some(data_offset);
            }
        }

        None
    }

    /// Get statistics
    pub fn entry_count(&self) -> u32 {
        self.header.entry_count
    }

    /// Get table size
    pub fn table_size(&self) -> u32 {
        self.header.table_size
    }
}

/// Build a single shard from its entries
fn build_shard_auto_size(shard_id: usize, entries: Vec<(String, u32, u64)>) -> Shard {
    if entries.is_empty() {
        return Shard {
            shard_id,
            table: Vec::new(),
            strings: Vec::new(),
        };
    }

    // Use 0.6 load factor for faster builds (40% empty space reduces collisions dramatically)
    let desired_load = 0.60f64;
    let needed = ((entries.len() as f64) / desired_load).ceil() as usize;
    let capacity = needed.next_power_of_two().max(16);
    let mask = capacity - 1;

    // Build string pool for this shard with bulk writes
    let estimated_pool_size: usize = entries.iter().map(|(p, _, _)| 2 + p.len() + 1).sum();
    let mut strings = Vec::with_capacity(estimated_pool_size);
    let mut string_offsets = Vec::with_capacity(entries.len());

    unsafe {
        let ptr: *mut u8 = strings.as_mut_ptr();
        let mut offset = 0;

        for (pattern, _, _) in &entries {
            string_offsets.push(offset);

            let len = pattern.len() as u16;
            let bytes = pattern.as_bytes();

            // Write length
            std::ptr::copy_nonoverlapping(len.to_le_bytes().as_ptr(), ptr.add(offset), 2);
            offset += 2;

            // Write string
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.add(offset), bytes.len());
            offset += bytes.len();

            // Null terminator
            *ptr.add(offset) = 0;
            offset += 1;
        }

        strings.set_len(offset);
    }

    // Build with FxHashMap (fast!), then convert to linear-probed array
    let mut map: FxHashMap<u64, (u32, u32)> = FxHashMap::default();
    for (idx, (_pattern, pattern_id, hash)) in entries.iter().enumerate() {
        map.insert(*hash, (string_offsets[idx] as u32, *pattern_id));
    }

    // Now serialize to linear-probed table
    let mut table = vec![HashEntry::empty(); capacity];
    for (hash, (string_offset, pattern_id)) in map.into_iter() {
        let mut pos = (hash as usize) & mask;

        // Linear probing - should be fast since we have 40% empty space
        while !table[pos].is_empty() {
            pos = (pos + 1) & mask;
        }

        table[pos] = HashEntry {
            hash,
            string_offset,
            pattern_id,
        };
    }

    Shard {
        shard_id,
        table,
        strings,
    }
}

/// Compute XXH64 with fixed seed for stable, portable on-disk hashing
const HASH_SEED_1: u64 = 0;

#[inline]
fn compute_hash(s: &str) -> u64 {
    xxh64(s.as_bytes(), HASH_SEED_1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_hash_table() {
        let mut builder = LiteralHashBuilder::new(MatchMode::CaseSensitive);
        builder.add_pattern("test1", 0);
        builder.add_pattern("test2", 1);
        builder.add_pattern("test3", 2);

        let pattern_data = vec![(0, 100), (1, 200), (2, 300)];
        let bytes = builder.build(&pattern_data).unwrap();

        let hash = LiteralHash::from_buffer(&bytes, MatchMode::CaseSensitive).unwrap();
        assert_eq!(hash.lookup("test1"), Some(0));
        assert_eq!(hash.lookup("test2"), Some(1));
        assert_eq!(hash.lookup("test3"), Some(2));
        assert_eq!(hash.lookup("test4"), None);

        assert_eq!(hash.get_data_offset(0), Some(100));
        assert_eq!(hash.get_data_offset(1), Some(200));
        assert_eq!(hash.get_data_offset(2), Some(300));
    }

    #[test]
    fn test_hash_collisions() {
        let mut builder = LiteralHashBuilder::new(MatchMode::CaseSensitive);
        // Add many patterns to force collisions
        for i in 0..100 {
            let pattern = format!("pattern_{}", i);
            builder.add_pattern(&pattern, i);
        }

        let pattern_data: Vec<_> = (0..100).map(|i| (i, i * 10)).collect();
        let bytes = builder.build(&pattern_data).unwrap();

        let hash = LiteralHash::from_buffer(&bytes, MatchMode::CaseSensitive).unwrap();
        for i in 0..100 {
            assert_eq!(hash.lookup(&format!("pattern_{}", i)), Some(i));
        }
    }
}
