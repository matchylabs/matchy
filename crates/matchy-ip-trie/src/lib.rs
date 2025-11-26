//! IP Tree Builder - Binary Trie for IP Address Lookups
//!
//! Builds a binary search tree for IP address lookups with CIDR prefix support.
//! Supports both IPv4 and IPv6 addresses.

use std::fmt;
use std::net::IpAddr;

// Validation module for IP tree structures
pub mod validation;

// Re-export validation types for convenience
pub use validation::{validate_ip_tree, IpTreeStats, IpTreeValidationResult};
/// Error type for IP tree operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpTreeError {
    /// Invalid pattern or input
    InvalidPattern(String),
    /// Resource limit exceeded
    ResourceLimitExceeded(String),
    /// Other error
    Other(String),
}

impl fmt::Display for IpTreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpTreeError::InvalidPattern(msg) => write!(f, "Invalid pattern: {}", msg),
            IpTreeError::ResourceLimitExceeded(msg) => {
                write!(f, "Resource limit exceeded: {}", msg)
            }
            IpTreeError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for IpTreeError {}

/// Record size - determines node size in binary format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordSize {
    /// 24-bit records (3 bytes per record, 6 bytes per node)
    Bits24 = 24,
    /// 28-bit records (3.5 bytes per record, 7 bytes per node)
    Bits28 = 28,
    /// 32-bit records (4 bytes per record, 8 bytes per node)
    Bits32 = 32,
}

impl RecordSize {
    /// Get the size of a node (2 records) in bytes
    pub fn node_bytes(self) -> usize {
        match self {
            RecordSize::Bits24 => 6,
            RecordSize::Bits28 => 7,
            RecordSize::Bits32 => 8,
        }
    }
}

/// IP tree builder using arena allocation
pub struct IpTreeBuilder {
    /// Record size for the tree
    record_size: RecordSize,
    /// All nodes in the tree (arena)
    nodes: Vec<Node>,
    /// IP version (determines tree depth)
    ip_version: IpVersion,
}

/// IP version for the tree
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpVersion {
    V4,
    V6,
}

/// A node in the IP tree
#[derive(Debug, Clone)]
struct Node {
    /// Left child (bit 0)
    left: NodePointer,
    /// Right child (bit 1)
    right: NodePointer,
}

/// Node pointer - can point to another node, data, or be empty
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodePointer {
    /// Points to another node (value is node ID)
    Node(u32),
    /// Points to data section (data offset, prefix length)
    /// Prefix length is tracked to enable proper longest-prefix matching:
    /// - When inserting a less-specific prefix after a more-specific one, we can compare
    /// - More specific (longer prefix) always wins
    /// - This doesn't affect the on-disk format, only the building logic
    Data(u32, u8),
    /// Empty (not found marker)
    Empty,
}

impl IpTreeBuilder {
    /// Create a new IPv4 tree builder
    pub fn new_v4(record_size: RecordSize) -> Self {
        let mut builder = Self {
            record_size,
            nodes: Vec::new(),
            ip_version: IpVersion::V4,
        };
        // Allocate root node
        builder.nodes.push(Node::new_empty());
        builder
    }

    /// Create a new IPv6 tree builder (can include IPv4)
    pub fn new_v6(record_size: RecordSize) -> Self {
        let mut builder = Self {
            record_size,
            nodes: Vec::new(),
            ip_version: IpVersion::V6,
        };
        // Allocate root node
        builder.nodes.push(Node::new_empty());
        builder
    }

    /// Reserve capacity for nodes to avoid reallocation
    ///
    /// # Arguments
    /// * `capacity` - Expected number of nodes
    pub fn reserve_nodes(&mut self, capacity: usize) {
        self.nodes
            .reserve(capacity.saturating_sub(self.nodes.len()));
    }

    /// Insert an IP address or CIDR range with associated data offset
    ///
    /// # Arguments
    /// * `addr` - IP address (v4 or v6)
    /// * `prefix_len` - Network prefix length (netmask)
    /// * `data_offset` - Offset into the data section
    pub fn insert(
        &mut self,
        addr: IpAddr,
        prefix_len: u8,
        data_offset: u32,
    ) -> Result<(), IpTreeError> {
        match addr {
            IpAddr::V4(v4) => {
                if self.ip_version == IpVersion::V6 {
                    // Insert IPv4 into IPv6 tree (as IPv4-mapped at ::ffff:0:0/96)
                    let bits = ipv4_to_bits(v4) as u128;
                    self.insert_bits_u128(bits, 96 + prefix_len, data_offset)
                } else {
                    // Pure IPv4 tree
                    if prefix_len > 32 {
                        return Err(IpTreeError::InvalidPattern(format!(
                            "IPv4 prefix length {} exceeds 32",
                            prefix_len
                        )));
                    }
                    let bits = ipv4_to_bits(v4) as u128;
                    self.insert_bits_u128(bits << 96, prefix_len, data_offset)
                }
            }
            IpAddr::V6(v6) => {
                if self.ip_version == IpVersion::V4 {
                    return Err(IpTreeError::InvalidPattern(
                        "Cannot insert IPv6 address into IPv4-only tree".to_string(),
                    ));
                }
                if prefix_len > 128 {
                    return Err(IpTreeError::InvalidPattern(format!(
                        "IPv6 prefix length {} exceeds 128",
                        prefix_len
                    )));
                }
                let bits = bits_to_u128(ipv6_to_bits(v6));
                self.insert_bits_u128(bits, prefix_len, data_offset)
            }
        }
    }

    /// Insert bits into tree using iterative approach (avoids borrow checker issues)
    fn insert_bits_u128(
        &mut self,
        bits: u128,
        prefix_len: u8,
        data_offset: u32,
    ) -> Result<(), IpTreeError> {
        let max_depth = match self.ip_version {
            IpVersion::V4 => 32,
            IpVersion::V6 => 128,
        };

        if prefix_len > max_depth {
            return Err(IpTreeError::InvalidPattern(format!(
                "Prefix length {} exceeds maximum {}",
                prefix_len, max_depth
            )));
        }

        let mut node_id = 0u32; // Start at root

        for depth in 0..prefix_len {
            // Get bit at current depth
            let bit = ((bits >> (127 - depth)) & 1) as u8;

            // Check what the current node's child pointer is
            let child_ptr_value = {
                let current_node = &self.nodes[node_id as usize];
                if bit == 0 {
                    current_node.left
                } else {
                    current_node.right
                }
            };

            if depth + 1 == prefix_len {
                // Reached target depth - need to set this edge to data
                // BUT: Check if there's already a Node pointer here (more specific routes exist deeper)
                match child_ptr_value {
                    NodePointer::Empty => {
                        // Empty - set to our data
                        let current_node = &mut self.nodes[node_id as usize];
                        if bit == 0 {
                            current_node.left = NodePointer::Data(data_offset, prefix_len);
                        } else {
                            current_node.right = NodePointer::Data(data_offset, prefix_len);
                        }
                        return Ok(());
                    }
                    NodePointer::Data(_existing_offset, existing_prefix_len) => {
                        // Existing data - check if our prefix is more specific
                        if prefix_len >= existing_prefix_len {
                            // Our prefix is more specific (or equal) - replace it
                            let current_node = &mut self.nodes[node_id as usize];
                            if bit == 0 {
                                current_node.left = NodePointer::Data(data_offset, prefix_len);
                            } else {
                                current_node.right = NodePointer::Data(data_offset, prefix_len);
                            }
                        }
                        // Otherwise keep the existing (more specific) data
                        return Ok(());
                    }
                    NodePointer::Node(child_node_id) => {
                        // There's already a node here, meaning more specific prefixes exist deeper.
                        // We're inserting a less specific prefix (e.g., /24) after more specific ones (e.g., /32).
                        // We need to set all EMPTY children of this subtree to point to our data,
                        // while preserving any existing data pointers (the more specific routes).
                        self.backfill_less_specific(child_node_id, data_offset, prefix_len);
                        return Ok(());
                    }
                }
            }

            // Need to go deeper
            match child_ptr_value {
                NodePointer::Empty => {
                    // Allocate new node
                    let new_id = self.allocate_node();
                    // Update the parent's pointer
                    let current_node = &mut self.nodes[node_id as usize];
                    if bit == 0 {
                        current_node.left = NodePointer::Node(new_id);
                    } else {
                        current_node.right = NodePointer::Node(new_id);
                    }
                    node_id = new_id;
                }
                NodePointer::Node(child_id) => {
                    // Continue to existing node
                    node_id = child_id;
                }
                NodePointer::Data(existing_data_offset, existing_prefix_len) => {
                    // Hit existing data before reaching target depth.
                    // This means a less specific prefix already exists (e.g., /24)
                    // and we're trying to insert a more specific one (e.g., /32).
                    //
                    // We need to:
                    // 1. Convert this data leaf into a node
                    // 2. Make both children point to the existing data (to preserve less specific match)
                    // 3. Continue down the tree to insert the more specific prefix

                    let new_node_id = self.allocate_node();

                    // Make both children of the new node point to the existing data
                    // This preserves the less specific match for all IPs under this prefix
                    self.nodes[new_node_id as usize].left =
                        NodePointer::Data(existing_data_offset, existing_prefix_len);
                    self.nodes[new_node_id as usize].right =
                        NodePointer::Data(existing_data_offset, existing_prefix_len);

                    // Update parent to point to new node instead of data
                    let current_node = &mut self.nodes[node_id as usize];
                    if bit == 0 {
                        current_node.left = NodePointer::Node(new_node_id);
                    } else {
                        current_node.right = NodePointer::Node(new_node_id);
                    }

                    // Continue traversal from the new node
                    node_id = new_node_id;
                }
            }
        }

        Ok(())
    }

    /// Allocate a new node and return its ID
    fn allocate_node(&mut self) -> u32 {
        let id = self.nodes.len() as u32;
        self.nodes.push(Node::new_empty());
        id
    }

    /// Backfill a subtree with less-specific prefix data
    ///
    /// When inserting a less specific prefix (e.g., /24) after more specific ones (e.g., /32),
    /// we need to fill in gaps left by the more specific routes.
    ///
    /// With prefix length tracking, we can now properly distinguish:
    /// - Empty pointers (fill with new data)
    /// - Less-specific data (replace with new, more specific data)
    /// - More-specific data (leave alone)
    ///
    /// # Arguments
    /// * `node_id` - Root of the subtree to backfill
    /// * `data_offset` - Data offset for the less specific prefix
    /// * `prefix_len` - Prefix length of the data we're backfilling
    fn backfill_less_specific(&mut self, node_id: u32, data_offset: u32, prefix_len: u8) {
        let (left_ptr, right_ptr) = {
            let node = &self.nodes[node_id as usize];
            (node.left, node.right)
        };

        // Process left child
        match left_ptr {
            NodePointer::Empty => {
                // Empty - fill with new data
                let node = &mut self.nodes[node_id as usize];
                node.left = NodePointer::Data(data_offset, prefix_len);
            }
            NodePointer::Data(_, existing_prefix_len) => {
                // Existing data - replace only if we're more specific
                if prefix_len > existing_prefix_len {
                    let node = &mut self.nodes[node_id as usize];
                    node.left = NodePointer::Data(data_offset, prefix_len);
                }
                // Otherwise keep the existing data (it's more specific)
            }
            NodePointer::Node(child_id) => {
                // Recurse into subtree
                self.backfill_less_specific(child_id, data_offset, prefix_len);
            }
        }

        // Process right child
        match right_ptr {
            NodePointer::Empty => {
                // Empty - fill with new data
                let node = &mut self.nodes[node_id as usize];
                node.right = NodePointer::Data(data_offset, prefix_len);
            }
            NodePointer::Data(_, existing_prefix_len) => {
                // Existing data - replace only if we're more specific
                if prefix_len > existing_prefix_len {
                    let node = &mut self.nodes[node_id as usize];
                    node.right = NodePointer::Data(data_offset, prefix_len);
                }
                // Otherwise keep the existing data (it's more specific)
            }
            NodePointer::Node(child_id) => {
                // Recurse into subtree
                self.backfill_less_specific(child_id, data_offset, prefix_len);
            }
        }
    }

    /// Build the tree and return serialized bytes
    ///
    /// Returns: (tree_bytes, node_count)
    pub fn build(&self) -> Result<(Vec<u8>, u32), IpTreeError> {
        let node_count = self.nodes.len() as u32;
        let node_size = self.record_size.node_bytes();
        let tree_size = node_count as usize * node_size;

        let mut tree_bytes = vec![0u8; tree_size];

        // Write each node from the arena
        for (node_id, node) in self.nodes.iter().enumerate() {
            self.write_node(&mut tree_bytes, node_id, node, node_count)?;
        }

        Ok((tree_bytes, node_count))
    }

    /// Write a single node to the tree bytes
    fn write_node(
        &self,
        tree: &mut [u8],
        node_id: usize,
        node: &Node,
        node_count: u32,
    ) -> Result<(), IpTreeError> {
        let left_value = self.pointer_to_value(node.left, node_count);
        let right_value = self.pointer_to_value(node.right, node_count);

        match self.record_size {
            RecordSize::Bits24 => self.write_24bit_node(tree, node_id, left_value, right_value),
            RecordSize::Bits28 => self.write_28bit_node(tree, node_id, left_value, right_value),
            RecordSize::Bits32 => self.write_32bit_node(tree, node_id, left_value, right_value),
        }
    }

    /// Convert node pointer to numeric value
    /// Note: prefix_len is discarded here - it's only used during building
    fn pointer_to_value(&self, pointer: NodePointer, node_count: u32) -> u32 {
        match pointer {
            NodePointer::Empty => node_count, // "not found" marker
            NodePointer::Node(id) => {
                // Validate node ID is within bounds
                assert!(
                    id < node_count,
                    "Invalid node ID {} >= node_count {}",
                    id,
                    node_count
                );
                id
            }
            NodePointer::Data(offset, _prefix_len) => {
                // Validate this won't underflow when read back
                // Reader does: record - node_count - 16
                // So we need: (node_count + 16 + offset) >= (node_count + 16)
                // Which is always true for valid offsets, but let's validate the addition won't overflow
                node_count
                    .checked_add(16)
                    .and_then(|base| base.checked_add(offset))
                    .unwrap_or_else(|| {
                        panic!(
                        "Data pointer overflow: node_count={} + 16 + offset={} exceeds u32::MAX",
                        node_count, offset
                    )
                    })
            }
        }
    }

    /// Write 24-bit node (6 bytes per node)
    fn write_24bit_node(
        &self,
        tree: &mut [u8],
        node_id: usize,
        left: u32,
        right: u32,
    ) -> Result<(), IpTreeError> {
        let offset = node_id * 6;
        if offset + 6 > tree.len() {
            return Err(IpTreeError::Other(format!(
                "Node offset {} exceeds tree size",
                offset
            )));
        }

        // Left record (3 bytes, big-endian)
        tree[offset] = ((left >> 16) & 0xFF) as u8;
        tree[offset + 1] = ((left >> 8) & 0xFF) as u8;
        tree[offset + 2] = (left & 0xFF) as u8;

        // Right record (3 bytes, big-endian)
        tree[offset + 3] = ((right >> 16) & 0xFF) as u8;
        tree[offset + 4] = ((right >> 8) & 0xFF) as u8;
        tree[offset + 5] = (right & 0xFF) as u8;

        Ok(())
    }

    /// Write 28-bit node (7 bytes per node)
    fn write_28bit_node(
        &self,
        tree: &mut [u8],
        node_id: usize,
        left: u32,
        right: u32,
    ) -> Result<(), IpTreeError> {
        let offset = node_id * 7;
        if offset + 7 > tree.len() {
            return Err(IpTreeError::Other(format!(
                "Node offset {} exceeds tree size",
                offset
            )));
        }

        // Layout: [Left 24 bits][Middle 8 bits][Right 24 bits]
        // Middle byte: 4 high bits of left + 4 high bits of right

        // Left low 24 bits
        tree[offset] = ((left >> 16) & 0xFF) as u8;
        tree[offset + 1] = ((left >> 8) & 0xFF) as u8;
        tree[offset + 2] = (left & 0xFF) as u8;

        // Middle byte: left high 4 bits in upper nibble, right high 4 bits in lower nibble
        let left_high = ((left >> 24) & 0x0F) as u8;
        let right_high = ((right >> 24) & 0x0F) as u8;
        tree[offset + 3] = (left_high << 4) | right_high;

        // Right low 24 bits
        tree[offset + 4] = ((right >> 16) & 0xFF) as u8;
        tree[offset + 5] = ((right >> 8) & 0xFF) as u8;
        tree[offset + 6] = (right & 0xFF) as u8;

        Ok(())
    }

    /// Write 32-bit node (8 bytes per node)
    fn write_32bit_node(
        &self,
        tree: &mut [u8],
        node_id: usize,
        left: u32,
        right: u32,
    ) -> Result<(), IpTreeError> {
        let offset = node_id * 8;
        if offset + 8 > tree.len() {
            return Err(IpTreeError::Other(format!(
                "Node offset {} exceeds tree size",
                offset
            )));
        }

        // Left record (4 bytes, big-endian)
        tree[offset] = ((left >> 24) & 0xFF) as u8;
        tree[offset + 1] = ((left >> 16) & 0xFF) as u8;
        tree[offset + 2] = ((left >> 8) & 0xFF) as u8;
        tree[offset + 3] = (left & 0xFF) as u8;

        // Right record (4 bytes, big-endian)
        tree[offset + 4] = ((right >> 24) & 0xFF) as u8;
        tree[offset + 5] = ((right >> 16) & 0xFF) as u8;
        tree[offset + 6] = ((right >> 8) & 0xFF) as u8;
        tree[offset + 7] = (right & 0xFF) as u8;

        Ok(())
    }
}

impl Node {
    fn new_empty() -> Self {
        Self {
            left: NodePointer::Empty,
            right: NodePointer::Empty,
        }
    }
}

/// Convert IPv4 address to 32-bit integer
fn ipv4_to_bits(addr: std::net::Ipv4Addr) -> u32 {
    let octets = addr.octets();
    ((octets[0] as u32) << 24)
        | ((octets[1] as u32) << 16)
        | ((octets[2] as u32) << 8)
        | (octets[3] as u32)
}

/// Convert IPv6 address to 128-bit integer (as two u64s)
fn ipv6_to_bits(addr: std::net::Ipv6Addr) -> (u64, u64) {
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

/// Convert two u64s to u128
fn bits_to_u128(bits: (u64, u64)) -> u128 {
    ((bits.0 as u128) << 64) | (bits.1 as u128)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_to_bits() {
        let addr = std::net::Ipv4Addr::new(192, 168, 1, 1);
        let bits = ipv4_to_bits(addr);
        assert_eq!(bits, 0xC0A80101);
    }

    #[test]
    fn test_new_v4_builder() {
        let builder = IpTreeBuilder::new_v4(RecordSize::Bits24);
        assert_eq!(builder.ip_version, IpVersion::V4);
        assert_eq!(builder.nodes.len(), 1); // Should have root node
    }

    #[test]
    fn test_build_empty_tree() {
        let builder = IpTreeBuilder::new_v4(RecordSize::Bits24);
        let result = builder.build();
        assert!(result.is_ok());
        let (bytes, node_count) = result.unwrap();
        assert_eq!(node_count, 1); // Just root
        assert_eq!(bytes.len(), 6); // One node with 24-bit records
    }

    #[test]
    fn test_insert_single_ipv4() {
        use std::net::Ipv4Addr;

        let mut builder = IpTreeBuilder::new_v4(RecordSize::Bits24);
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Insert with /32 prefix (exact host)
        let result = builder.insert(addr, 32, 100); // data offset 100
        assert!(result.is_ok());

        // Should have allocated more nodes
        assert!(builder.nodes.len() > 1);
    }

    #[test]
    fn test_insert_ipv4_cidr() {
        use std::net::Ipv4Addr;

        let mut builder = IpTreeBuilder::new_v4(RecordSize::Bits24);
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0));

        // Insert /16 network
        let result = builder.insert(addr, 16, 200);
        assert!(result.is_ok());

        // Build the tree
        let build_result = builder.build();
        assert!(build_result.is_ok());
        let (bytes, node_count) = build_result.unwrap();

        // Should have some nodes (at least root + 16 levels)
        assert!(node_count > 1);
        assert_eq!(bytes.len(), node_count as usize * 6); // 24-bit records = 6 bytes/node
    }

    #[test]
    fn test_insert_multiple_ipv4() {
        use std::net::Ipv4Addr;

        let mut builder = IpTreeBuilder::new_v4(RecordSize::Bits24);

        // Insert multiple addresses
        builder
            .insert(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24, 100)
            .unwrap();
        builder
            .insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8, 200)
            .unwrap();
        builder
            .insert(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12, 300)
            .unwrap();

        let (bytes, node_count) = builder.build().unwrap();

        // Should have built a non-trivial tree
        assert!(node_count > 3);
        assert_eq!(bytes.len(), node_count as usize * 6);
    }

    #[test]
    fn test_insert_ipv6() {
        use std::net::Ipv6Addr;

        let mut builder = IpTreeBuilder::new_v6(RecordSize::Bits24);
        let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));

        let result = builder.insert(addr, 64, 100);
        assert!(result.is_ok());

        let (bytes, node_count) = builder.build().unwrap();
        assert!(node_count > 1);
        assert_eq!(bytes.len(), node_count as usize * 6);
    }

    #[test]
    fn test_invalid_prefix_length() {
        use std::net::Ipv4Addr;

        let mut builder = IpTreeBuilder::new_v4(RecordSize::Bits24);
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Try to insert with prefix > 32 for IPv4
        let result = builder.insert(addr, 33, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv6_in_ipv4_tree_fails() {
        use std::net::Ipv6Addr;

        let mut builder = IpTreeBuilder::new_v4(RecordSize::Bits24);
        let addr = IpAddr::V6(Ipv6Addr::LOCALHOST);

        // Should fail to insert IPv6 into IPv4-only tree
        let result = builder.insert(addr, 128, 100);
        assert!(result.is_err());
    }
}
