//! IP tree validation for untrusted binary data
//!
//! This module validates IP tree structures to ensure they are safe to use.
//! Validates tree traversal, detects cycles, checks for orphaned nodes, and validates pointers.

use std::collections::HashSet;

/// Validation result for IP tree structures
#[derive(Debug, Clone)]
pub struct IpTreeValidationResult {
    /// Critical errors that make the structure unusable
    pub errors: Vec<String>,
    /// Warnings about potential issues (non-fatal)
    pub warnings: Vec<String>,
    /// Statistics gathered during validation
    pub stats: IpTreeStats,
}

/// Statistics gathered during IP tree validation
#[derive(Debug, Clone, Default)]
pub struct IpTreeStats {
    /// Number of nodes in the tree
    pub node_count: u32,
    /// Number of nodes visited during traversal
    pub nodes_visited: u32,
    /// Number of orphaned nodes (unreachable from root)
    pub orphaned_count: u32,
    /// Whether a cycle was detected
    pub cycle_detected: bool,
    /// Number of invalid pointers found
    pub invalid_pointers: u32,
}

impl IpTreeValidationResult {
    fn new(node_count: u32) -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
            stats: IpTreeStats {
                node_count,
                ..Default::default()
            },
        }
    }

    /// Check if validation passed (no errors)
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validate IP tree structure with full traversal
///
/// Validates:
/// - Tree traversal from root
/// - Cycle detection
/// - Node pointer validity
/// - Orphaned nodes detection
/// - Record bounds checking
///
/// # Arguments
///
/// * `buffer` - The buffer containing the IP tree data
/// * `tree_size` - Size of the tree section in bytes
/// * `node_count` - Number of nodes in the tree
/// * `node_bytes` - Size of each node in bytes (6, 7, or 8)
/// * `ip_version` - IP version (4 or 6)
///
/// # Returns
///
/// A `IpTreeValidationResult` with errors, warnings, and statistics
pub fn validate_ip_tree(
    buffer: &[u8],
    tree_size: usize,
    node_count: u32,
    node_bytes: usize,
    ip_version: u16,
) -> IpTreeValidationResult {
    let mut result = IpTreeValidationResult::new(node_count);

    if node_count == 0 {
        return result;
    }

    // Determine tree depth based on IP version
    let tree_depth = match ip_version {
        4 => 32,  // IPv4: 32 bits
        6 => 128, // IPv6: 128 bits
        _ => {
            result
                .errors
                .push(format!("Invalid IP version: {}", ip_version));
            return result;
        }
    };

    // Track current path for cycle detection, and all visited for statistics
    let mut path = HashSet::new();
    let mut all_visited = HashSet::new();
    let mut cycle_detected = false;
    let mut invalid_pointers = 0;

    // Traverse tree starting from root (node 0)
    let traverse_result = traverse_ip_tree_node(
        buffer,
        0, // Start at root
        0, // Depth 0
        tree_depth,
        node_count,
        node_bytes,
        tree_size,
        &mut path,
        &mut all_visited,
        &mut cycle_detected,
        &mut invalid_pointers,
    );

    if let Err(e) = traverse_result {
        result.errors.push(format!("Tree traversal error: {}", e));
    }

    // Gather statistics
    result.stats.nodes_visited = all_visited.len() as u32;
    result.stats.orphaned_count = node_count.saturating_sub(all_visited.len() as u32);
    result.stats.cycle_detected = cycle_detected;
    result.stats.invalid_pointers = invalid_pointers;

    // Check for orphaned nodes
    if result.stats.orphaned_count > 0 {
        result.warnings.push(format!(
            "Found {} orphaned nodes (exist in tree but unreachable from root)",
            result.stats.orphaned_count
        ));
    }

    // Report critical issues
    if cycle_detected {
        result
            .errors
            .push("CRITICAL: Tree cycle detected - would cause infinite loops!".to_string());
    }

    if invalid_pointers > 0 {
        result.errors.push(format!(
            "CRITICAL: {} invalid node pointers detected!",
            invalid_pointers
        ));
    }

    result
}

/// Recursively traverse IP tree node and validate structure
///
/// The `path` set tracks ancestors in the current traversal path for cycle detection.
/// The `all_visited` set tracks all nodes ever visited for statistics (orphan detection).
#[allow(clippy::too_many_arguments)]
fn traverse_ip_tree_node(
    buffer: &[u8],
    node_index: u32,
    depth: usize,
    max_depth: usize,
    node_count: u32,
    node_bytes: usize,
    tree_size: usize,
    path: &mut HashSet<u32>,
    all_visited: &mut HashSet<u32>,
    cycle_detected: &mut bool,
    invalid_pointers: &mut u32,
) -> Result<(), String> {
    // Check for cycles - only an error if this node is an ancestor in current path
    if path.contains(&node_index) {
        *cycle_detected = true;
        return Err(format!("Cycle detected at node {}", node_index));
    }

    // Skip if already fully validated (legitimate node sharing/reuse)
    if all_visited.contains(&node_index) {
        return Ok(());
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

    // Add to current path and all visited
    path.insert(node_index);
    all_visited.insert(node_index);

    // Calculate node offset
    let node_offset = (node_index as usize) * node_bytes;
    if node_offset + node_bytes > tree_size {
        path.remove(&node_index);
        return Err(format!(
            "Node {} offset {} exceeds tree size {}",
            node_index, node_offset, tree_size
        ));
    }

    if node_offset + node_bytes > buffer.len() {
        path.remove(&node_index);
        return Err(format!("Node {} would read beyond buffer", node_index));
    }

    // Read both records (left and right)
    let (left_record, right_record) = match node_bytes {
        6 => {
            // 24-bit records (3 bytes each)
            let left = (buffer[node_offset] as u32) << 16
                | (buffer[node_offset + 1] as u32) << 8
                | (buffer[node_offset + 2] as u32);
            let right = (buffer[node_offset + 3] as u32) << 16
                | (buffer[node_offset + 4] as u32) << 8
                | (buffer[node_offset + 5] as u32);
            (left, right)
        }
        7 => {
            // 28-bit records (7 bytes total per node)
            // Layout: | left[23..0] | left[27..24]:right[27..24] | right[23..0] |
            // Bytes:  |  0  1  2    |            3               |   4  5  6    |
            let middle = buffer[node_offset + 3];
            let left_low = (buffer[node_offset] as u32) << 16
                | (buffer[node_offset + 1] as u32) << 8
                | (buffer[node_offset + 2] as u32);
            let left_high = ((middle >> 4) & 0x0F) as u32;
            let left = (left_high << 24) | left_low;

            let right_low = (buffer[node_offset + 4] as u32) << 16
                | (buffer[node_offset + 5] as u32) << 8
                | (buffer[node_offset + 6] as u32);
            let right_high = (middle & 0x0F) as u32;
            let right = (right_high << 24) | right_low;
            (left, right)
        }
        8 => {
            // 32-bit records (4 bytes each)
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
            path.remove(&node_index);
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
                path,
                all_visited,
                cycle_detected,
                invalid_pointers,
            )?;
        }
        // If left_record >= node_count, it's a data pointer or empty (validated elsewhere)

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
                path,
                all_visited,
                cycle_detected,
                invalid_pointers,
            )?;
        }
        // If right_record >= node_count, it's a data pointer or empty
    }

    // Remove from path when backtracking
    path.remove(&node_index);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_empty_tree() {
        let buffer = vec![0u8; 100];
        let result = validate_ip_tree(&buffer, 100, 0, 6, 4);
        assert!(result.is_valid());
        assert_eq!(result.stats.node_count, 0);
    }

    #[test]
    fn test_validate_invalid_ip_version() {
        let buffer = vec![0u8; 100];
        let result = validate_ip_tree(&buffer, 100, 10, 6, 99); // Invalid version
        assert!(!result.is_valid());
        assert!(result.errors.iter().any(|e| e.contains("Invalid IP")));
    }

    #[test]
    fn test_validate_invalid_node_bytes() {
        let buffer = vec![0u8; 100];
        let result = validate_ip_tree(&buffer, 100, 1, 5, 4); // Invalid node_bytes
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("Invalid node_bytes")));
    }
}
