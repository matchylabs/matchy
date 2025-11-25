//! MMDB Search Tree Traversal
//!
//! Implements binary search tree traversal for IP address lookups.
//! The tree uses a compact binary representation where each node contains
//! two records (left and right) that point to either:
//! - Another node (continue traversal)
//! - A data section offset (found)
//! - A "not found" marker

use super::format::MmdbHeader;
use super::types::{MmdbError, RecordSize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Result of an IP lookup
#[derive(Debug, Clone, PartialEq)]
pub struct LookupResult {
    /// Offset into the data section (relative to data section start)
    pub data_offset: u32,
    /// Network prefix length (netmask)
    pub prefix_len: u8,
}

/// Search tree for IP address lookups
pub struct SearchTree<'a> {
    /// The raw file data containing the tree
    data: &'a [u8],
    /// Parsed header information
    header: &'a MmdbHeader,
}

impl<'a> SearchTree<'a> {
    /// Create a new search tree
    pub fn new(data: &'a [u8], header: &'a MmdbHeader) -> Self {
        Self { data, header }
    }

    /// Look up an IP address
    pub fn lookup(&self, ip: IpAddr) -> Result<Option<LookupResult>, MmdbError> {
        match ip {
            IpAddr::V4(addr) => self.lookup_v4(addr),
            IpAddr::V6(addr) => self.lookup_v6(addr),
        }
    }

    /// Look up an IPv4 address
    pub fn lookup_v4(&self, addr: Ipv4Addr) -> Result<Option<LookupResult>, MmdbError> {
        use super::types::IpVersion;

        // Check if this is an IPv6 tree
        let (mut node, mut depth) = if self.header.ip_version == IpVersion::V6 {
            // IPv4 addresses in IPv6 trees require finding the IPv4 start node first.
            // Per MMDB spec and libmaxminddb, we traverse 96 zero bits (::ffff:0:0/96)
            // to reach the IPv4 address space within the IPv6 tree.
            self.find_ipv4_start_node()?
        } else {
            // Pure IPv4 tree - start at root
            (0u32, 0u8)
        };

        // Now traverse the IPv4 address bits
        let bits = ipv4_to_bits(addr);

        for bit_index in 0..32 {
            let bit = ((bits >> (31 - bit_index)) & 1) as u8;
            let record = self.read_record(node as usize, bit)?;

            if record == self.header.node_count {
                return Ok(None);
            } else if record < self.header.node_count {
                node = record;
                depth += 1;
            } else {
                let data_offset = self.calculate_data_offset(record)?;
                // For IPv4 lookups, report the prefix as IPv4 prefix length
                // (depth includes the 96 bits traversed for IPv6 tree, so subtract them)
                let ipv4_prefix = if depth >= 96 {
                    depth - 96 + 1
                } else {
                    depth + 1
                };
                return Ok(Some(LookupResult {
                    data_offset,
                    prefix_len: ipv4_prefix,
                }));
            }
        }

        Ok(None)
    }

    /// Look up an IPv6 address
    pub fn lookup_v6(&self, addr: Ipv6Addr) -> Result<Option<LookupResult>, MmdbError> {
        // Convert IPv6 to bits
        let bits = ipv6_to_bits(addr);

        let mut node = 0u32;
        let mut depth = 0u8;
        let max_depth = 128;

        for bit_index in 0..max_depth {
            // Extract bit from 128-bit value
            let bit = if bit_index < 64 {
                (bits.0 >> (63 - bit_index)) & 1
            } else {
                (bits.1 >> (127 - bit_index)) & 1
            };

            let record = self.read_record(node as usize, bit as u8)?;

            if record == self.header.node_count {
                return Ok(None);
            } else if record < self.header.node_count {
                node = record;
                depth = bit_index + 1;
            } else {
                let data_offset = self.calculate_data_offset(record)?;
                return Ok(Some(LookupResult {
                    data_offset,
                    prefix_len: depth + 1,
                }));
            }
        }

        Ok(None)
    }

    /// Read a record from a node
    ///
    /// Each node contains two records. `side` determines which:
    /// - 0 = left record (for IP bit 0)
    /// - 1 = right record (for IP bit 1)
    fn read_record(&self, node: usize, side: u8) -> Result<u32, MmdbError> {
        if node as u32 >= self.header.node_count {
            return Err(MmdbError::InvalidFormat(format!(
                "Node index {} exceeds node count {}",
                node, self.header.node_count
            )));
        }

        match self.header.record_size {
            RecordSize::Bits24 => self.read_24bit_record(node, side),
            RecordSize::Bits28 => self.read_28bit_record(node, side),
            RecordSize::Bits32 => self.read_32bit_record(node, side),
        }
    }

    /// Read a 24-bit record (3 bytes per record, 6 bytes per node)
    fn read_24bit_record(&self, node: usize, side: u8) -> Result<u32, MmdbError> {
        let node_offset = node * 6; // 6 bytes per node
        let record_offset = node_offset + (side as usize * 3);

        if record_offset + 3 > self.header.tree_size {
            return Err(MmdbError::InvalidFormat(format!(
                "Record offset {} exceeds tree size {}",
                record_offset, self.header.tree_size
            )));
        }

        // Read 3 bytes in big-endian order
        let b0 = self.data[record_offset] as u32;
        let b1 = self.data[record_offset + 1] as u32;
        let b2 = self.data[record_offset + 2] as u32;

        Ok((b0 << 16) | (b1 << 8) | b2)
    }

    /// Read a 28-bit record (3.5 bytes per record, 7 bytes per node)
    ///
    /// Layout: [Left 24 bits][Middle 8 bits][Right 24 bits]
    /// Middle byte contains 4 high bits of left + 4 high bits of right
    fn read_28bit_record(&self, node: usize, side: u8) -> Result<u32, MmdbError> {
        let node_offset = node * 7; // 7 bytes per node

        if node_offset + 7 > self.header.tree_size {
            return Err(MmdbError::InvalidFormat(format!(
                "Node offset {} exceeds tree size {}",
                node_offset, self.header.tree_size
            )));
        }

        let bytes = &self.data[node_offset..node_offset + 7];

        if side == 0 {
            // Left record: bytes[0..3] with 4 high bits from middle byte
            let high_bits = ((bytes[3] >> 4) & 0x0F) as u32;
            let low_bits = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32);
            Ok((high_bits << 24) | low_bits)
        } else {
            // Right record: bytes[4..7] with 4 low bits from middle byte
            let high_bits = (bytes[3] & 0x0F) as u32;
            let low_bits = ((bytes[4] as u32) << 16) | ((bytes[5] as u32) << 8) | (bytes[6] as u32);
            Ok((high_bits << 24) | low_bits)
        }
    }

    /// Read a 32-bit record (4 bytes per record, 8 bytes per node)
    fn read_32bit_record(&self, node: usize, side: u8) -> Result<u32, MmdbError> {
        let node_offset = node * 8; // 8 bytes per node
        let record_offset = node_offset + (side as usize * 4);

        if record_offset + 4 > self.header.tree_size {
            return Err(MmdbError::InvalidFormat(format!(
                "Record offset {} exceeds tree size {}",
                record_offset, self.header.tree_size
            )));
        }

        // Read 4 bytes in big-endian order
        let b0 = self.data[record_offset] as u32;
        let b1 = self.data[record_offset + 1] as u32;
        let b2 = self.data[record_offset + 2] as u32;
        let b3 = self.data[record_offset + 3] as u32;

        Ok((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
    }

    /// Calculate data section offset from record value
    ///
    /// Per MMDB spec:
    /// - Record value > node_count means it points to data
    /// - Formula: data_offset = (record_value - node_count) - 16
    /// - The 16 is the data section separator size
    fn calculate_data_offset(&self, record: u32) -> Result<u32, MmdbError> {
        if record <= self.header.node_count {
            return Err(MmdbError::InvalidFormat(format!(
                "Record {} is not a data pointer (node_count = {})",
                record, self.header.node_count
            )));
        }

        // Per spec: subtract node count, then subtract 16 for separator
        let offset_before_separator =
            record.checked_sub(self.header.node_count).ok_or_else(|| {
                MmdbError::InvalidFormat(format!(
                    "Record {} - node_count {} underflow",
                    record, self.header.node_count
                ))
            })?;

        let offset = offset_before_separator.checked_sub(16).ok_or_else(|| {
            MmdbError::InvalidFormat(format!(
                "Data pointer {} - 16 underflow (record={}, node_count={})",
                offset_before_separator, record, self.header.node_count
            ))
        })?;

        Ok(offset)
    }

    /// Find the IPv4 start node in an IPv6 tree
    ///
    /// Per MMDB spec, IPv4 addresses in IPv6 trees are accessed via the
    /// ::ffff:0:0/96 prefix. We traverse 96 zero bits to find where the
    /// IPv4 address space begins.
    ///
    /// Returns (node, depth) where node is the starting node for IPv4 lookups
    /// and depth is 96 (the number of bits traversed).
    fn find_ipv4_start_node(&self) -> Result<(u32, u8), MmdbError> {
        let mut node = 0u32;

        // Traverse 96 zero bits (left record each time)
        for _ in 0..96 {
            let record = self.read_record(node as usize, 0)?;

            if record == self.header.node_count {
                // IPv4 space not found in this tree
                return Ok((node, 96));
            } else if record < self.header.node_count {
                node = record;
            } else {
                // Shouldn't hit data in the first 96 bits, but handle it
                return Ok((node, 96));
            }
        }

        Ok((node, 96))
    }
}

/// Convert IPv4 address to 32-bit integer
fn ipv4_to_bits(addr: Ipv4Addr) -> u32 {
    let octets = addr.octets();
    ((octets[0] as u32) << 24)
        | ((octets[1] as u32) << 16)
        | ((octets[2] as u32) << 8)
        | (octets[3] as u32)
}

/// Convert IPv6 address to 128-bit integer (as two u64s)
fn ipv6_to_bits(addr: Ipv6Addr) -> (u64, u64) {
    let segments = addr.segments();
    let high = ((segments[0] as u64) << 48)
        | ((segments[1] as u64) << 32)
        | ((segments[2] as u64) << 16)
        | (segments[3] as u64);
    let low = ((segments[4] as u64) << 48)
        | ((segments[5] as u64) << 32)
        | ((segments[6] as u64) << 16)
        | (segments[7] as u64);
    (high, low)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_to_bits() {
        let addr = Ipv4Addr::new(192, 168, 1, 1);
        let bits = ipv4_to_bits(addr);
        assert_eq!(bits, 0xC0A80101);
    }

    #[test]
    fn test_ipv6_to_bits() {
        let addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let (high, low) = ipv6_to_bits(addr);
        assert_eq!(high, 0x20010db800000000);
        assert_eq!(low, 0x0000000000000001);
    }

    #[test]
    fn test_read_24bit_record() {
        use super::super::types::IpVersion;

        // Create a small test tree with 24-bit records
        // Node 0: left=1, right=2
        let mut data = vec![0u8; 1000];
        data[0] = 0x00; // left record high byte
        data[1] = 0x00;
        data[2] = 0x01; // left = 1
        data[3] = 0x00; // right record high byte
        data[4] = 0x00;
        data[5] = 0x02; // right = 2

        let header = MmdbHeader {
            node_count: 10,
            record_size: RecordSize::Bits24,
            ip_version: IpVersion::V6,
            tree_size: 60, // 10 nodes * 6 bytes
        };

        let tree = SearchTree::new(&data, &header);

        assert_eq!(tree.read_24bit_record(0, 0).unwrap(), 1);
        assert_eq!(tree.read_24bit_record(0, 1).unwrap(), 2);
    }

    #[test]
    fn test_read_28bit_record() {
        use super::super::types::IpVersion;

        // Create test data for 28-bit records
        let mut data = vec![0u8; 1000];
        // Node 0 with 28-bit records
        // Left: 0x1000001, Right: 0x2000002
        data[0] = 0x00; // left low 24 bits
        data[1] = 0x00;
        data[2] = 0x01;
        data[3] = 0x12; // middle byte: 0x1 for left high, 0x2 for right high
        data[4] = 0x00; // right low 24 bits
        data[5] = 0x00;
        data[6] = 0x02;

        let header = MmdbHeader {
            node_count: 10,
            record_size: RecordSize::Bits28,
            ip_version: IpVersion::V6,
            tree_size: 70, // 10 nodes * 7 bytes
        };

        let tree = SearchTree::new(&data, &header);

        assert_eq!(tree.read_28bit_record(0, 0).unwrap(), 0x1000001);
        assert_eq!(tree.read_28bit_record(0, 1).unwrap(), 0x2000002);
    }

    #[test]
    fn test_calculate_data_offset() {
        use super::super::types::IpVersion;

        let header = MmdbHeader {
            node_count: 100,
            record_size: RecordSize::Bits24,
            ip_version: IpVersion::V6,
            tree_size: 600,
        };

        let tree = SearchTree::new(&[], &header);

        // Record 116 -> data offset 0
        // (116 - 100 - 16 = 0)
        assert_eq!(tree.calculate_data_offset(116).unwrap(), 0);

        // Record 200 -> data offset 84
        // (200 - 100 - 16 = 84)
        assert_eq!(tree.calculate_data_offset(200).unwrap(), 84);
    }

    #[test]
    fn test_lookup_with_real_database() {
        // This test uses the actual GeoLite2-Country.mmdb file
        let data = include_bytes!("../../tests/data/GeoLite2-Country.mmdb");

        // Parse header
        let header = MmdbHeader::from_file(data).unwrap();
        let tree = SearchTree::new(data, &header);

        // Test a known IP (1.1.1.1 - Cloudflare, should be in database)
        let ip = Ipv4Addr::new(1, 1, 1, 1);
        let result = tree.lookup_v4(ip).unwrap();

        // Should find something for this well-known IP
        assert!(result.is_some(), "Should find data for 1.1.1.1");

        if let Some(lookup_result) = result {
            assert!(
                lookup_result.data_offset > 0,
                "Data offset should be non-zero"
            );
            assert!(
                lookup_result.prefix_len > 0,
                "Prefix length should be positive"
            );
            assert!(
                lookup_result.prefix_len <= 32,
                "IPv4 prefix should be <= 32"
            );
        }

        // Test another well-known IP
        let ip2 = Ipv4Addr::new(8, 8, 8, 8);
        let result2 = tree.lookup_v4(ip2).unwrap();
        assert!(result2.is_some(), "Should find data for 8.8.8.8");
    }
}
