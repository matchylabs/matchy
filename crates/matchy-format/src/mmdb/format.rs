//! MMDB Binary Format Parsing
//!
//! This module handles parsing the MMDB binary format with minimal heap allocation.
//! Only essential header information is extracted; everything else stays in mmap.
//!
//! Design:
//! - Find metadata marker (slice search, no allocation)
//! - Extract only: node_count, record_size, ip_version (~16 bytes on heap)
//! - Tree traversal works with pure offsets (zero allocation)
//! - Data decoding only allocates when returning results to users

use super::types::{record_size_from_bits, IpVersion, MmdbError, RecordSize, METADATA_MARKER};
use matchy_data_format::{DataDecoder, DataValue};

/// MMDB file header - minimal heap usage
///
/// Contains only the essential information needed for IP lookups.
/// Total heap usage: ~16 bytes.
#[derive(Debug, Clone, Copy)]
pub struct MmdbHeader {
    /// Number of nodes in the search tree
    pub node_count: u32,
    /// Record size in bits (24, 28, or 32)
    pub record_size: RecordSize,
    /// IP version (4 or 6)
    pub ip_version: IpVersion,
    /// Size of the search tree in bytes
    pub tree_size: usize,
}

impl MmdbHeader {
    /// Parse MMDB file and extract minimal header information
    ///
    /// Only extracts fields needed for IP lookups. Metadata stays in mmap.
    pub fn from_file(data: &[u8]) -> Result<Self, MmdbError> {
        // Find metadata marker
        let marker_offset = find_metadata_marker(data)?;

        // Metadata comes AFTER the marker (verified from libmaxminddb source)
        // The metadata section starts right after the marker bytes
        let metadata_offset = marker_offset + METADATA_MARKER.len();
        let metadata_bytes = &data[metadata_offset..];

        // Decode metadata as MMDB data starting at offset 0
        let decoder = DataDecoder::new(metadata_bytes, 0);
        let metadata_value = decoder
            .decode(0)
            .map_err(|e| MmdbError::InvalidMetadata(format!("Failed to decode metadata: {}", e)))?;

        // Extract required fields (temporary allocation during parsing)
        let (node_count, record_size_bits, ip_version_num) = match metadata_value {
            DataValue::Map(ref map) => {
                let node_count = extract_uint(map, "node_count")?;
                let record_size = extract_uint(map, "record_size")? as u16;
                let ip_version = extract_uint(map, "ip_version")?;
                (node_count, record_size, ip_version)
            }
            _ => {
                return Err(MmdbError::InvalidMetadata(
                    "Metadata is not a map".to_string(),
                ))
            }
        };

        let record_size = record_size_from_bits(record_size_bits)?;

        let ip_version = match ip_version_num {
            4 => IpVersion::V4,
            6 => IpVersion::V6,
            _ => {
                return Err(MmdbError::InvalidMetadata(format!(
                    "Invalid IP version: {}",
                    ip_version_num
                )))
            }
        };

        // Calculate tree size
        let tree_size = (node_count as usize) * record_size.node_bytes();

        Ok(MmdbHeader {
            node_count: node_count as u32,
            record_size,
            ip_version,
            tree_size,
        })
    }
}

/// Optional metadata access (zero-copy, parses on-demand)
///
/// This provides access to non-essential metadata fields without
/// allocating until actually requested.
pub struct MmdbMetadata<'a> {
    raw_data: &'a [u8],
    metadata_offset: usize,
}

impl<'a> MmdbMetadata<'a> {
    /// Create metadata accessor from mmap'd data
    pub fn from_file(data: &'a [u8]) -> Result<Self, MmdbError> {
        let metadata_start = find_metadata_marker(data)?;
        let metadata_offset = metadata_start + METADATA_MARKER.len();

        Ok(MmdbMetadata {
            raw_data: data,
            metadata_offset,
        })
    }

    /// Get full metadata as DataValue (allocates on-demand)
    pub fn as_value(&self) -> Result<DataValue, MmdbError> {
        let decoder = DataDecoder::new(&self.raw_data[self.metadata_offset..], 0);
        decoder
            .decode(0)
            .map_err(|e| MmdbError::InvalidMetadata(e.to_string()))
    }
}

/// Find the metadata marker in MMDB file (zero allocation)
///
/// The marker "\xAB\xCD\xEFMaxMind.com" appears somewhere in the last 128KB
/// of the file. The metadata comes AFTER the marker.
///
/// Note: If there are multiple markers (unlikely but possible), we want the LAST one.
pub fn find_metadata_marker(data: &[u8]) -> Result<usize, MmdbError> {
    const SEARCH_SIZE: usize = 128 * 1024; // 128KB

    if data.len() < METADATA_MARKER.len() {
        return Err(MmdbError::MetadataNotFound);
    }

    // Start searching from the end, but only within the last 128KB
    let search_start = if data.len() > SEARCH_SIZE {
        data.len() - SEARCH_SIZE
    } else {
        0
    };

    // Search for the marker, keeping track of the LAST occurrence
    // (libmaxminddb does this to handle files with multiple markers)
    let mut last_marker = None;
    for i in search_start..=(data.len() - METADATA_MARKER.len()) {
        if &data[i..i + METADATA_MARKER.len()] == METADATA_MARKER {
            last_marker = Some(i);
        }
    }

    last_marker.ok_or(MmdbError::MetadataNotFound)
}

// Helper functions to extract values from metadata map (temporary during parsing)

fn extract_uint(
    map: &std::collections::HashMap<String, DataValue>,
    key: &str,
) -> Result<u64, MmdbError> {
    match map.get(key) {
        Some(DataValue::Uint16(n)) => Ok(*n as u64),
        Some(DataValue::Uint32(n)) => Ok(*n as u64),
        Some(DataValue::Uint64(n)) => Ok(*n),
        Some(_) => Err(MmdbError::InvalidMetadata(format!(
            "Field '{}' is not an unsigned integer",
            key
        ))),
        None => Err(MmdbError::InvalidMetadata(format!(
            "Required field '{}' not found",
            key
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_metadata_marker() {
        let data = include_bytes!("../../tests/data/GeoLite2-Country.mmdb");
        let marker_offset = find_metadata_marker(data);
        assert!(marker_offset.is_ok(), "Should find metadata marker");

        let offset = marker_offset.unwrap();
        println!("Total file size: {} bytes", data.len());
        println!("Marker found at offset: {}", offset);
        println!(
            "Marker: {:?}",
            &data[offset..offset + METADATA_MARKER.len()]
        );

        assert!(offset > 0, "Marker should not be at start of file");
        assert_eq!(
            &data[offset..offset + METADATA_MARKER.len()],
            METADATA_MARKER
        );

        // Check what's around the marker
        let after_marker = offset + METADATA_MARKER.len();
        let before_marker = offset.saturating_sub(20);
        println!(
            "20 bytes before marker: {:02x?}",
            &data[before_marker..offset]
        );
        println!(
            "Bytes after marker: {} bytes remaining",
            data.len() - after_marker
        );
        if data.len() > after_marker {
            println!(
                "First 20 bytes after marker: {:02x?}",
                &data[after_marker..after_marker.min(data.len())]
            );
        }
    }

    #[test]
    fn test_parse_header_minimal() {
        let data = include_bytes!("../../tests/data/GeoLite2-Country.mmdb");
        let header = MmdbHeader::from_file(data);
        if let Err(ref e) = header {
            println!("Error parsing header: {}", e);
        }
        assert!(header.is_ok(), "Should parse header successfully");

        let header = header.unwrap();
        assert!(header.node_count > 0, "Should have nodes");
        assert!(header.tree_size > 0, "Tree should have size");

        // Record size should be valid
        match header.record_size {
            RecordSize::Bits24 | RecordSize::Bits28 | RecordSize::Bits32 => {}
        }

        // IP version should be valid
        match header.ip_version {
            IpVersion::V4 | IpVersion::V6 => {}
        }

        println!("Header: {:?}", header);
        println!("Heap usage: ~{} bytes", std::mem::size_of_val(&header));
    }

    #[test]
    fn test_metadata_on_demand() {
        let data = include_bytes!("../../tests/data/GeoLite2-Country.mmdb");
        let metadata = MmdbMetadata::from_file(data);
        assert!(metadata.is_ok(), "Should create metadata accessor");

        let metadata = metadata.unwrap();

        // Parse on-demand from mmap using as_value()
        let metadata_value = metadata.as_value();
        assert!(metadata_value.is_ok());

        if let DataValue::Map(ref map) = metadata_value.unwrap() {
            // Check database_type
            if let Some(DataValue::String(db_type)) = map.get("database_type") {
                assert_eq!(db_type, "GeoLite2-Country");
            }

            // Check build_epoch
            if let Some(epoch_value) = map.get("build_epoch") {
                let epoch_num = match epoch_value {
                    DataValue::Uint32(n) => *n as u64,
                    DataValue::Uint64(n) => *n,
                    _ => panic!("build_epoch has unexpected type"),
                };
                println!("Build epoch: {}", epoch_num);
                assert!(epoch_num > 0);
            }
        } else {
            panic!("Metadata should be a map");
        }
    }

    #[test]
    fn test_metadata_not_found() {
        let data = b"not a valid mmdb file";
        let result = find_metadata_marker(data);
        assert!(result.is_err());
        assert!(matches!(result, Err(MmdbError::MetadataNotFound)));
    }
}
