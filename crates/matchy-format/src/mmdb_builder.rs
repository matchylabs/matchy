//! Unified MMDB Database Builder
//!
//! Builds MMDB-format databases containing both IP address data and pattern matching data.
//! Automatically detects whether input rows are IP addresses (including CIDRs) or patterns.

use matchy_data_format::{DataEncoder, DataValue};
use crate::error::FormatError;
use matchy_match_mode::MatchMode;
use matchy_ip_trie::IpTreeBuilder;
use matchy_literal_hash::LiteralHashBuilder;
use crate::mmdb::types::RecordSize;
use matchy_paraglob::ParaglobBuilder;
use matchy_glob::GlobPattern;
use rustc_hash::FxHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

/// Entry type classification
#[derive(Debug, Clone)]
pub enum EntryType {
    /// IP address or CIDR block with prefix length
    IpAddress {
        /// IP address
        addr: IpAddr,
        /// Prefix length (0-32 for IPv4, 0-128 for IPv6)
        prefix_len: u8,
    },
    /// Literal string (exact match, goes in hash table)
    Literal(String),
    /// Glob pattern (wildcard match, goes in Aho-Corasick)
    Glob(String),
}

/// Lightweight entry reference (just entry type + offset, no data)
#[derive(Debug, Clone)]
struct EntryRef {
    entry_type: EntryType,
    data_offset: u32,
}

/// Unified database builder
pub struct MmdbBuilder {
    /// Lightweight entry references (key + offset only)
    entries: Vec<EntryRef>,
    /// Data encoder for streaming data encoding
    data_encoder: DataEncoder,
    /// Deduplication cache (data hash -> offset)
    data_cache: HashMap<u64, u32>,
    match_mode: MatchMode,
    /// Optional custom database type name
    database_type: Option<String>,
    /// Optional custom description (language -> text)
    description: HashMap<String, String>,
}

impl MmdbBuilder {
    /// Create a new builder
    pub fn new(match_mode: MatchMode) -> Self {
        Self {
            entries: Vec::new(),
            data_encoder: DataEncoder::new(),
            data_cache: HashMap::new(),
            match_mode,
            database_type: None,
            description: HashMap::new(),
        }
    }

    /// Set a custom database type name
    ///
    /// If not set, defaults to "Paraglob-Combined-IP-Pattern" or "Paraglob-IP"
    ///
    /// # Example
    /// ```
    /// use matchy::mmdb_builder::MmdbBuilder;
    /// use matchy::MatchMode;
    ///
    /// let builder = MmdbBuilder::new(MatchMode::CaseSensitive)
    ///     .with_database_type("MyCompany-ThreatIntel");
    /// ```
    pub fn with_database_type(mut self, db_type: impl Into<String>) -> Self {
        self.database_type = Some(db_type.into());
        self
    }

    /// Add a description in a specific language
    ///
    /// Can be called multiple times for different languages.
    /// If not called, defaults to English description.
    ///
    /// # Example
    /// ```
    /// use matchy::mmdb_builder::MmdbBuilder;
    /// use matchy::MatchMode;
    ///
    /// let builder = MmdbBuilder::new(MatchMode::CaseSensitive)
    ///     .with_description("en", "My custom threat database")
    ///     .with_description("es", "Mi base de datos de amenazas personalizada");
    /// ```
    pub fn with_description(
        mut self,
        language: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        self.description.insert(language.into(), text.into());
        self
    }

    /// Add an entry with auto-detection
    ///
    /// Automatically detects whether the key is an IP address, literal string, or glob pattern.
    /// For explicit control, use `add_ip()`, `add_literal()`, or `add_glob()`.
    pub fn add_entry(
        &mut self,
        key: &str,
        data: HashMap<String, DataValue>,
    ) -> Result<(), FormatError> {
        let entry_type = Self::detect_entry_type(key)?;
        let data_offset = self.encode_and_deduplicate_data(data);

        self.entries.push(EntryRef {
            entry_type,
            data_offset,
        });

        Ok(())
    }

    /// Add a literal string pattern (exact match only, no wildcards)
    ///
    /// Use this when the string contains characters like '*', '?', or '[' that should be
    /// matched literally rather than as glob wildcards.
    ///
    /// # Example
    /// ```
    /// # use matchy::{DatabaseBuilder, MatchMode, DataValue};
    /// # use std::collections::HashMap;
    /// let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
    /// let mut data = HashMap::new();
    /// data.insert("note".to_string(), DataValue::String("literal".to_string()));
    ///
    /// // This has '[' but we want to match it literally
    /// builder.add_literal("file[1].txt", data)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn add_literal(
        &mut self,
        pattern: &str,
        data: HashMap<String, DataValue>,
    ) -> Result<(), FormatError> {
        let data_offset = self.encode_and_deduplicate_data(data);
        self.entries.push(EntryRef {
            entry_type: EntryType::Literal(pattern.to_string()),
            data_offset,
        });
        Ok(())
    }

    /// Add a glob pattern (with wildcard matching)
    ///
    /// Use this to explicitly mark a pattern for glob matching, even if it doesn't
    /// contain obvious wildcard characters.
    ///
    /// # Example
    /// ```
    /// # use matchy::{DatabaseBuilder, MatchMode, DataValue};
    /// # use std::collections::HashMap;
    /// let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
    /// let mut data = HashMap::new();
    /// data.insert("category".to_string(), DataValue::String("malware".to_string()));
    ///
    /// builder.add_glob("*.evil.com", data)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn add_glob(
        &mut self,
        pattern: &str,
        data: HashMap<String, DataValue>,
    ) -> Result<(), FormatError> {
        let data_offset = self.encode_and_deduplicate_data(data);
        self.entries.push(EntryRef {
            entry_type: EntryType::Glob(pattern.to_string()),
            data_offset,
        });
        Ok(())
    }

    /// Encode data and deduplicate to save memory
    fn encode_and_deduplicate_data(&mut self, data: HashMap<String, DataValue>) -> u32 {
        // Fast hash computation without string allocation
        let data_value = DataValue::Map(data);
        let mut hasher = FxHasher::default();
        data_value.hash(&mut hasher);
        let hash = hasher.finish();

        // Check cache
        if let Some(&offset) = self.data_cache.get(&hash) {
            return offset;
        }

        // Encode and cache
        let offset = self.data_encoder.encode(&data_value);
        self.data_cache.insert(hash, offset);
        offset
    }

    /// Add an IP address or CIDR block
    ///
    /// Use this to explicitly mark an entry as an IP address. Will return an error
    /// if the string is not a valid IP address or CIDR notation.
    ///
    /// # Arguments
    /// * `ip_or_cidr` - IP address or CIDR range (e.g., "192.168.1.0/24")
    /// * `data` - HashMap of key-value pairs to associate with the IP
    ///
    /// # Errors
    /// Returns an error if the IP address or CIDR format is invalid.
    ///
    /// # Example
    /// ```
    /// # use matchy::{DatabaseBuilder, MatchMode, DataValue};
    /// # use std::collections::HashMap;
    /// let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
    /// let mut data = HashMap::new();
    /// data.insert("country".to_string(), DataValue::String("US".to_string()));
    ///
    /// builder.add_ip("192.168.1.0/24", data)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn add_ip(
        &mut self,
        ip_or_cidr: &str,
        data: HashMap<String, DataValue>,
    ) -> Result<(), FormatError> {
        let entry_type = Self::parse_ip_entry(ip_or_cidr)?;
        let data_offset = self.encode_and_deduplicate_data(data);

        self.entries.push(EntryRef {
            entry_type,
            data_offset,
        });
        Ok(())
    }

    /// Parse IP address or CIDR (used by add_ip)
    fn parse_ip_entry(key: &str) -> Result<EntryType, FormatError> {
        // Try parsing as plain IP address first
        if let Ok(addr) = key.parse::<IpAddr>() {
            let prefix_len = if addr.is_ipv4() { 32 } else { 128 };
            return Ok(EntryType::IpAddress { addr, prefix_len });
        }

        // Check for CIDR notation
        if let Some(slash_pos) = key.find('/') {
            let addr_str = &key[..slash_pos];
            let prefix_str = &key[slash_pos + 1..];

            if let (Ok(addr), Ok(prefix_len)) =
                (addr_str.parse::<IpAddr>(), prefix_str.parse::<u8>())
            {
                // Validate prefix length
                let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
                if prefix_len <= max_prefix {
                    return Ok(EntryType::IpAddress { addr, prefix_len });
                }
            }
        }

        Err(FormatError::InvalidPattern(format!(
            "Invalid IP address or CIDR: {}",
            key
        )))
    }

    /// Auto-detect if key is an IP/CIDR, literal, or glob pattern
    ///
    /// Supports explicit type prefixes for disambiguation:
    /// - `literal:` - Force literal string matching (strips prefix)
    /// - `glob:` - Force glob pattern matching (strips prefix)
    /// - `ip:` - Force IP address parsing (strips prefix)
    ///
    /// Without a prefix, auto-detection is used:
    /// 1. Try parsing as IP address/CIDR
    /// 2. If contains glob chars (*, ?, [), validate as glob pattern
    /// 3. Otherwise treat as literal string
    ///
    /// # Examples
    /// ```
    /// # use matchy::mmdb_builder::{MmdbBuilder, EntryType};
    /// # use matchy::MatchMode;
    /// // Auto-detection
    /// assert!(matches!(MmdbBuilder::detect_entry_type("1.2.3.4"), Ok(EntryType::IpAddress { .. })));
    /// assert!(matches!(MmdbBuilder::detect_entry_type("*.example.com"), Ok(EntryType::Glob(_))));
    /// assert!(matches!(MmdbBuilder::detect_entry_type("evil.com"), Ok(EntryType::Literal(_))));
    ///
    /// // Explicit type control
    /// assert!(matches!(MmdbBuilder::detect_entry_type("literal:*.not-a-glob.com"), Ok(EntryType::Literal(_))));
    /// assert!(matches!(MmdbBuilder::detect_entry_type("glob:no-wildcards.com"), Ok(EntryType::Glob(_))));
    /// ```
    pub fn detect_entry_type(key: &str) -> Result<EntryType, FormatError> {
        // Check for explicit type prefixes first
        if let Some(stripped) = key.strip_prefix("literal:") {
            // Force literal matching - strip prefix and treat as literal
            return Ok(EntryType::Literal(stripped.to_string()));
        }

        if let Some(stripped) = key.strip_prefix("glob:") {
            // Force glob matching - strip prefix and validate as glob
            // Use CaseSensitive for validation (mode doesn't matter for syntax checking)
            if GlobPattern::new(stripped, MatchMode::CaseSensitive).is_ok()
            {
                return Ok(EntryType::Glob(stripped.to_string()));
            }
            // If explicitly marked as glob but invalid syntax, return error
            return Err(FormatError::InvalidPattern(format!(
                "Invalid glob pattern syntax: {}",
                stripped
            )));
        }

        if let Some(stripped) = key.strip_prefix("ip:") {
            // Force IP parsing - strip prefix and parse as IP
            return Self::parse_ip_entry(stripped);
        }

        // No prefix - use auto-detection
        // Try parsing as IP address first (most specific)
        if Self::parse_ip_entry(key).is_ok() {
            return Self::parse_ip_entry(key);
        }

        // Check for glob pattern characters - but validate they form a valid glob
        if key.contains('*') || key.contains('?') || key.contains('[') {
            // Try to actually parse it as a glob to see if it's valid
            // Use CaseSensitive for validation (mode doesn't matter for syntax checking)
            if GlobPattern::new(key, MatchMode::CaseSensitive).is_ok() {
                return Ok(EntryType::Glob(key.to_string()));
            }
            // If it contains glob-like chars but isn't a valid glob, treat as literal
        }

        // Otherwise, treat as literal string
        Ok(EntryType::Literal(key.to_string()))
    }

    /// Build the unified MMDB database
    pub fn build(mut self) -> Result<Vec<u8>, FormatError> {
        // Data is already encoded - just extract from the builder
        let data_section = self.data_encoder.into_bytes();

        // Clear cache to free memory
        self.data_cache.clear();

        // Separate entries by type (using pre-encoded offsets)
        // Pre-allocate with capacity to avoid reallocation
        let entry_count = self.entries.len();
        let mut ip_entries = Vec::with_capacity(entry_count);
        let mut literal_entries = Vec::with_capacity(entry_count);
        let mut glob_entries = Vec::with_capacity(entry_count);

        for entry in &self.entries {
            match &entry.entry_type {
                EntryType::IpAddress { addr, prefix_len } => {
                    ip_entries.push((*addr, *prefix_len, entry.data_offset));
                }
                EntryType::Literal(pattern) => {
                    literal_entries.push((pattern.as_str(), entry.data_offset));
                }
                EntryType::Glob(pattern) => {
                    glob_entries.push((pattern.as_str(), entry.data_offset));
                }
            }
        }

        // Always build IP tree structure (even if empty) to maintain MMDB format
        // This ensures pattern-only databases still work with the Database API
        let (ip_tree_bytes, node_count, record_size, ip_version) = if !ip_entries.is_empty() {
            // Determine IP version needed
            let needs_v6 = ip_entries.iter().any(|(addr, _, _)| addr.is_ipv6());

            // Choose record size based on expected tree size
            // For /32 IPs, worst case is ~ip_count nodes
            // 24-bit: max 16,777,216 nodes (16M IPs)
            // 28-bit: max 268,435,456 nodes (268M IPs)
            // 32-bit: max 4,294,967,296 nodes (4.2B IPs)
            let estimated_nodes = ip_entries.len();
            let record_size = if estimated_nodes > 200_000_000 {
                // Over 200M IPs - use 32-bit for safety
                RecordSize::Bits32
            } else if estimated_nodes > 15_000_000 {
                // Over 15M IPs - use 28-bit
                RecordSize::Bits28
            } else {
                // Under 15M IPs - use 24-bit (most common)
                RecordSize::Bits24
            };

            // Sort IPs by prefix length (more specific first), then by address
            // This minimizes tree reorganization and backfill operations
            ip_entries.sort_unstable_by(|(addr1, prefix1, _), (addr2, prefix2, _)| {
                prefix2.cmp(prefix1).then_with(|| addr1.cmp(addr2))
            });

            let mut tree_builder = if needs_v6 {
                IpTreeBuilder::new_v6(record_size)
            } else {
                IpTreeBuilder::new_v4(record_size)
            };

            // Pre-allocate nodes (estimate: ~1.5x entries for typical CIDR distributions)
            tree_builder.reserve_nodes(estimated_nodes + estimated_nodes / 2);

            // Insert all IP entries using pre-encoded offsets
            for (addr, prefix_len, data_offset) in &ip_entries {
                tree_builder.insert(*addr, *prefix_len, *data_offset)?;
            }

            // Build the tree
            let (tree_bytes, node_cnt) = tree_builder.build()?;

            let ip_ver = if needs_v6 { 6 } else { 4 };
            (tree_bytes, node_cnt, record_size, ip_ver)
        } else {
            // Empty IP tree - create minimal valid tree
            let record_size = RecordSize::Bits24;
            let tree_builder = IpTreeBuilder::new_v4(record_size);
            let (tree_bytes, node_cnt) = tree_builder.build()?;
            (tree_bytes, node_cnt, record_size, 4)
        };

        // Build glob pattern section if we have glob entries (NOT literals)
        let (has_globs, glob_section_bytes) = if !glob_entries.is_empty() {
            let mut pattern_builder = ParaglobBuilder::new(self.match_mode);
            let mut pattern_data = Vec::with_capacity(glob_entries.len());

            for (pattern, data_offset) in &glob_entries {
                let pattern_id = pattern_builder.add_pattern(pattern)?;
                pattern_data.push((pattern_id, *data_offset));
            }

            let paraglob = pattern_builder.build()?;
            let paraglob_bytes = paraglob.buffer().to_vec();

            // Build complete pattern section: [total_size][paraglob_size][paraglob_data][mappings]
            let mut section = Vec::new();

            // Will fill in sizes at the end
            let size_placeholder = vec![0u8; 8]; // 2 u32s
            section.extend_from_slice(&size_placeholder);

            // Paraglob data
            section.extend_from_slice(&paraglob_bytes);

            // Mappings: pattern_count + data offsets
            let pattern_count = pattern_data.len() as u32;
            section.extend_from_slice(&pattern_count.to_le_bytes());
            for (_pattern_id, data_offset) in pattern_data {
                section.extend_from_slice(&data_offset.to_le_bytes());
            }

            // Fill in sizes
            let total_size = section.len() as u32;
            let paraglob_size = paraglob_bytes.len() as u32;
            section[0..4].copy_from_slice(&total_size.to_le_bytes());
            section[4..8].copy_from_slice(&paraglob_size.to_le_bytes());

            (true, section)
        } else {
            (false, Vec::new())
        };

        // Build literal hash table section for literal_entries
        let (has_literals, literal_section_bytes) = if !literal_entries.is_empty() {
            let mut literal_builder = LiteralHashBuilder::new(self.match_mode);
            let mut literal_pattern_data = Vec::with_capacity(literal_entries.len());

            for (next_pattern_id, (literal, data_offset)) in literal_entries.iter().enumerate() {
                literal_builder.add_pattern(literal, next_pattern_id as u32);
                literal_pattern_data.push((next_pattern_id as u32, *data_offset));
            }

            let literal_bytes = literal_builder.build(&literal_pattern_data)?;
            (true, literal_bytes)
        } else {
            (false, Vec::new())
        };

        // Assemble final database - always use MMDB format
        let mut database = Vec::new();

        // IP tree (empty or populated)
        database.extend_from_slice(&ip_tree_bytes);
        database
            .extend_from_slice(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"); // 16-byte separator

        // Data section
        database.extend_from_slice(&data_section);

        // Add padding to ensure paraglob section (if present) starts at 4-byte aligned offset
        // ParaglobHeader requires 4-byte alignment for zerocopy
        if has_globs {
            let current_offset = database.len() + 16; // +16 for "MMDB_PATTERN" separator
            let padding_needed = (4 - (current_offset % 4)) % 4;
            database.extend(std::iter::repeat_n(0u8, padding_needed));
        }

        // Add MMDB metadata section (always present)
        {
            // Build metadata map
            let mut metadata = HashMap::new();
            metadata.insert(
                "binary_format_major_version".to_string(),
                DataValue::Uint16(2),
            );
            metadata.insert(
                "binary_format_minor_version".to_string(),
                DataValue::Uint16(0),
            );
            metadata.insert(
                "build_epoch".to_string(),
                DataValue::Uint64(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                ),
            );
            // Database type - use custom if provided, otherwise auto-generate
            let db_type = self.database_type.clone().unwrap_or_else(|| {
                if has_globs || !literal_entries.is_empty() {
                    if !ip_entries.is_empty() {
                        "Paraglob-Combined-IP-Pattern".to_string()
                    } else {
                        "Paraglob-Pattern".to_string()
                    }
                } else {
                    "Paraglob-IP".to_string()
                }
            });
            metadata.insert("database_type".to_string(), DataValue::String(db_type));

            // Description - use custom if provided, otherwise use default
            let description_map = if self.description.is_empty() {
                let mut desc = HashMap::new();
                desc.insert(
                    "en".to_string(),
                    DataValue::String(
                        "Paraglob unified database with IP and pattern matching".to_string(),
                    ),
                );
                desc
            } else {
                self.description
                    .iter()
                    .map(|(k, v)| (k.clone(), DataValue::String(v.clone())))
                    .collect()
            };
            metadata.insert("description".to_string(), DataValue::Map(description_map));
            metadata.insert(
                "languages".to_string(),
                DataValue::Array(vec![DataValue::String("en".to_string())]),
            );
            metadata.insert(
                "ip_version".to_string(),
                DataValue::Uint16(ip_version as u16),
            );
            metadata.insert("node_count".to_string(), DataValue::Uint32(node_count));
            metadata.insert(
                "record_size".to_string(),
                DataValue::Uint16(match record_size {
                    RecordSize::Bits24 => 24,
                    RecordSize::Bits28 => 28,
                    RecordSize::Bits32 => 32,
                }),
            );

            // Add entry counts for easy inspection
            metadata.insert(
                "ip_entry_count".to_string(),
                DataValue::Uint32(ip_entries.len() as u32),
            );
            metadata.insert(
                "literal_entry_count".to_string(),
                DataValue::Uint32(literal_entries.len() as u32),
            );
            metadata.insert(
                "glob_entry_count".to_string(),
                DataValue::Uint32(glob_entries.len() as u32),
            );

            // Store match mode (0 = CaseSensitive, 1 = CaseInsensitive)
            let match_mode_value = match self.match_mode {
                MatchMode::CaseSensitive => 0u16,
                MatchMode::CaseInsensitive => 1u16,
            };
            metadata.insert(
                "match_mode".to_string(),
                DataValue::Uint16(match_mode_value),
            );

            // ALWAYS write section offset fields for fast loading (0 = not present)
            // This eliminates the need to scan the entire file for separators
            let tree_and_separator_size = ip_tree_bytes.len() + 16;
            let data_section_size = data_section.len();

            // Calculate padding before paraglob section for 4-byte alignment
            let padding_before_paraglob = if has_globs {
                let current_offset = tree_and_separator_size + data_section_size + 16; // +16 for separator
                (4 - (current_offset % 4)) % 4
            } else {
                0
            };

            // Pattern section offset (after tree + separator + data section + padding)
            // 0 means no pattern section present
            let pattern_offset = if has_globs {
                tree_and_separator_size + data_section_size + padding_before_paraglob + 16
            // +16 for "MMDB_PATTERN" separator
            } else {
                0 // No pattern section
            };
            metadata.insert(
                "pattern_section_offset".to_string(),
                DataValue::Uint32(pattern_offset as u32),
            );

            // Literal section offset (after pattern section if present)
            // 0 means no literal section present
            let literal_offset = if has_literals {
                if has_globs {
                    tree_and_separator_size
                        + data_section_size
                        + padding_before_paraglob
                        + 16
                        + glob_section_bytes.len()
                        + 16
                } else {
                    tree_and_separator_size + data_section_size + 16 // +16 for "MMDB_LITERAL" separator
                }
            } else {
                0 // No literal section
            };
            metadata.insert(
                "literal_section_offset".to_string(),
                DataValue::Uint32(literal_offset as u32),
            );

            // Encode metadata
            let mut meta_encoder = DataEncoder::new();
            let metadata_value = DataValue::Map(metadata);
            meta_encoder.encode(&metadata_value);
            let metadata_bytes = meta_encoder.into_bytes();

            // Save metadata for end of file (will be added after pattern section)
            // This ensures it's in the last 128KB for the metadata marker search

            // Add MMDB_PATTERN separator before globs (if any)
            if has_globs {
                database.extend_from_slice(b"MMDB_PATTERN\x00\x00\x00\x00");
                database.extend_from_slice(&glob_section_bytes);
            }

            // Add MMDB_LITERAL separator before literals (if any)
            if has_literals {
                database.extend_from_slice(b"MMDB_LITERAL\x00\x00\x00\x00");
                database.extend_from_slice(&literal_section_bytes);
            }

            // Add metadata at the END of the file so it's within the 128KB search window
            database.extend_from_slice(b"\xAB\xCD\xEFMaxMind.com");
            database.extend_from_slice(&metadata_bytes);
        }

        Ok(database)
    }

    /// Get statistics about the builder
    pub fn stats(&self) -> BuilderStats {
        let mut ip_count = 0;
        let mut literal_count = 0;
        let mut glob_count = 0;

        for entry in &self.entries {
            match &entry.entry_type {
                EntryType::IpAddress { .. } => ip_count += 1,
                EntryType::Literal(_) => literal_count += 1,
                EntryType::Glob(_) => glob_count += 1,
            }
        }

        BuilderStats {
            total_entries: self.entries.len(),
            ip_entries: ip_count,
            literal_entries: literal_count,
            glob_entries: glob_count,
        }
    }
}

/// Builder statistics
#[derive(Debug, Clone)]
pub struct BuilderStats {
    /// Total number of entries added
    pub total_entries: usize,
    /// Number of IP address/CIDR entries
    pub ip_entries: usize,
    /// Number of literal string entries (exact match)
    pub literal_entries: usize,
    /// Number of glob pattern entries (wildcard match)
    pub glob_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ip_address() {
        let result = MmdbBuilder::detect_entry_type("8.8.8.8").unwrap();
        match result {
            EntryType::IpAddress { addr, prefix_len } => {
                assert_eq!(addr.to_string(), "8.8.8.8");
                assert_eq!(prefix_len, 32);
            }
            _ => panic!("Expected IP address"),
        }
    }

    #[test]
    fn test_detect_cidr() {
        let result = MmdbBuilder::detect_entry_type("192.168.0.0/16").unwrap();
        match result {
            EntryType::IpAddress { addr, prefix_len } => {
                assert_eq!(addr.to_string(), "192.168.0.0");
                assert_eq!(prefix_len, 16);
            }
            _ => panic!("Expected CIDR"),
        }
    }

    #[test]
    fn test_detect_ipv6() {
        let result = MmdbBuilder::detect_entry_type("2001:4860:4860::8888").unwrap();
        match result {
            EntryType::IpAddress { addr, prefix_len } => {
                assert!(addr.is_ipv6());
                assert_eq!(prefix_len, 128);
            }
            _ => panic!("Expected IPv6"),
        }
    }

    #[test]
    fn test_detect_pattern_wildcard() {
        let result = MmdbBuilder::detect_entry_type("*.evil.com").unwrap();
        match result {
            EntryType::Glob(p) => assert_eq!(p, "*.evil.com"),
            _ => panic!("Expected glob pattern"),
        }
    }

    #[test]
    fn test_detect_pattern_literal() {
        let result = MmdbBuilder::detect_entry_type("evil.com").unwrap();
        match result {
            EntryType::Literal(p) => assert_eq!(p, "evil.com"),
            _ => panic!("Expected literal pattern"),
        }
    }

    // ========== Prefix Convention Tests ==========

    #[test]
    fn test_literal_prefix_forces_literal() {
        // String with glob chars should normally be a glob, but prefix forces literal
        let result = MmdbBuilder::detect_entry_type("literal:*.not-a-glob.com").unwrap();
        match result {
            EntryType::Literal(p) => assert_eq!(p, "*.not-a-glob.com"),
            _ => panic!("Expected literal, got: {:?}", result),
        }
    }

    #[test]
    fn test_literal_prefix_strips_correctly() {
        let result = MmdbBuilder::detect_entry_type("literal:evil.example.com").unwrap();
        match result {
            EntryType::Literal(p) => {
                assert_eq!(p, "evil.example.com");
                assert!(!p.starts_with("literal:"));
            }
            _ => panic!("Expected literal"),
        }
    }

    #[test]
    fn test_glob_prefix_forces_glob() {
        // String without wildcards should normally be literal, but prefix forces glob
        let result = MmdbBuilder::detect_entry_type("glob:no-wildcards.com").unwrap();
        match result {
            EntryType::Glob(p) => assert_eq!(p, "no-wildcards.com"),
            _ => panic!("Expected glob, got: {:?}", result),
        }
    }

    #[test]
    fn test_glob_prefix_with_wildcards() {
        let result = MmdbBuilder::detect_entry_type("glob:*.evil.com").unwrap();
        match result {
            EntryType::Glob(p) => {
                assert_eq!(p, "*.evil.com");
                assert!(!p.starts_with("glob:"));
            }
            _ => panic!("Expected glob"),
        }
    }

    #[test]
    fn test_glob_prefix_invalid_pattern() {
        // If explicitly marked as glob but has invalid glob syntax, should error
        let result = MmdbBuilder::detect_entry_type("glob:[unclosed");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid glob pattern syntax"));
    }

    #[test]
    fn test_ip_prefix_forces_ip() {
        let result = MmdbBuilder::detect_entry_type("ip:8.8.8.8").unwrap();
        match result {
            EntryType::IpAddress { addr, prefix_len } => {
                assert_eq!(addr.to_string(), "8.8.8.8");
                assert_eq!(prefix_len, 32);
            }
            _ => panic!("Expected IP address"),
        }
    }

    #[test]
    fn test_ip_prefix_with_cidr() {
        let result = MmdbBuilder::detect_entry_type("ip:10.0.0.0/8").unwrap();
        match result {
            EntryType::IpAddress { addr, prefix_len } => {
                assert_eq!(addr.to_string(), "10.0.0.0");
                assert_eq!(prefix_len, 8);
            }
            _ => panic!("Expected CIDR"),
        }
    }

    #[test]
    fn test_ip_prefix_invalid_ip() {
        let result = MmdbBuilder::detect_entry_type("ip:not-an-ip");
        assert!(result.is_err());
    }

    #[test]
    fn test_auto_detection_still_works() {
        // Without prefix, auto-detection should work as before
        assert!(matches!(
            MmdbBuilder::detect_entry_type("1.2.3.4"),
            Ok(EntryType::IpAddress { .. })
        ));
        assert!(matches!(
            MmdbBuilder::detect_entry_type("*.example.com"),
            Ok(EntryType::Glob(_))
        ));
        assert!(matches!(
            MmdbBuilder::detect_entry_type("example.com"),
            Ok(EntryType::Literal(_))
        ));
    }

    #[test]
    fn test_prefix_case_sensitive() {
        // Prefixes should be case-sensitive
        let result = MmdbBuilder::detect_entry_type("LITERAL:test.com").unwrap();
        // Should not match prefix, should auto-detect as literal
        match result {
            EntryType::Literal(p) => {
                // Should include the LITERAL: prefix since it wasn't recognized
                assert_eq!(p, "LITERAL:test.com");
            }
            _ => panic!("Expected literal"),
        }
    }

    #[test]
    fn test_literal_prefix_with_question_mark() {
        let result = MmdbBuilder::detect_entry_type("literal:file?.txt").unwrap();
        match result {
            EntryType::Literal(p) => assert_eq!(p, "file?.txt"),
            _ => panic!("Expected literal"),
        }
    }

    #[test]
    fn test_literal_prefix_with_brackets() {
        let result = MmdbBuilder::detect_entry_type("literal:file[1].txt").unwrap();
        match result {
            EntryType::Literal(p) => assert_eq!(p, "file[1].txt"),
            _ => panic!("Expected literal"),
        }
    }

    #[test]
    fn test_builder_add_entry_with_prefix() {
        // Integration test: add_entry should respect prefixes
        let mut builder = MmdbBuilder::new(MatchMode::CaseSensitive);

        // Force literal for a string that looks like a glob
        builder
            .add_entry("literal:*.test.com", HashMap::new())
            .unwrap();

        let stats = builder.stats();
        assert_eq!(stats.literal_entries, 1);
        assert_eq!(stats.glob_entries, 0);
    }

    #[test]
    fn test_builder_add_entry_glob_prefix() {
        let mut builder = MmdbBuilder::new(MatchMode::CaseSensitive);

        // Force glob for a string without wildcards
        builder.add_entry("glob:test.com", HashMap::new()).unwrap();

        let stats = builder.stats();
        assert_eq!(stats.glob_entries, 1);
        assert_eq!(stats.literal_entries, 0);
    }

    #[test]
    fn test_empty_prefix_value() {
        // Edge case: what if someone uses "literal:" with nothing after?
        let result = MmdbBuilder::detect_entry_type("literal:").unwrap();
        match result {
            EntryType::Literal(p) => assert_eq!(p, ""),
            _ => panic!("Expected literal"),
        }
    }
}
