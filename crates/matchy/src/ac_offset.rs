//! Offset-based Aho-Corasick Automaton
//!
//! This module implements an Aho-Corasick automaton that builds directly into
//! the binary offset-based format. Unlike traditional implementations, this
//! creates the serialized format during construction, allowing zero-copy
//! memory-mapped operation.
//!
//! # Design
//!
//! The automaton is stored as a single `Vec<u8>` containing:
//! - AC nodes with offset-based transitions
//! - Edge arrays referenced by nodes
//! - Pattern ID arrays referenced by nodes
//!
//! All operations (both building and matching) work directly on this buffer.

use crate::error::ParaglobError;
use crate::offset_format::{ACEdge, ACNodeHot, DenseLookup, StateKind};
use std::collections::{HashMap, VecDeque};
use std::mem;

/// Matching mode for the automaton
///
/// # Case-Insensitive Implementation
///
/// Case-insensitive mode uses a memory-efficient approach:
/// - Patterns are normalized to lowercase during automaton construction
/// - Input text is normalized to lowercase during search (using SIMD)
/// - This avoids doubling the automaton size (compared to storing both upper/lower transitions)
///
/// For ~16K PSL patterns, this reduces memory usage by approximately 50%.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    /// Case-sensitive matching
    CaseSensitive,
    /// Case-insensitive matching (patterns and text lowercased)
    CaseInsensitive,
}

/// Builder for constructing the offset-based AC automaton
///
/// This uses temporary in-memory structures during construction,
/// then serializes them into the final offset-based format.
struct ACBuilder {
    /// Temporary states during construction
    states: Vec<BuilderState>,
    /// Matching mode
    mode: MatchMode,
    /// Original patterns
    patterns: Vec<String>,
}

/// Temporary state structure used during construction
#[derive(Debug, Clone)]
struct BuilderState {
    transitions: HashMap<u8, u32>,
    failure: u32,
    outputs: Vec<u32>, // Pattern IDs
}

impl BuilderState {
    fn new(_id: u32, _depth: u8) -> Self {
        Self {
            transitions: HashMap::new(),
            failure: 0,
            outputs: Vec::new(),
        }
    }

    /// Classify state encoding based on transition count
    ///
    /// # State Encoding Selection
    ///
    /// - **Empty** (0 transitions): Terminal states only, no lookups needed
    /// - **One** (1 transition): Store inline, eliminates cache miss (75-80% of states)
    /// - **Sparse** (2-8 transitions): Linear search is optimal for this range
    /// - **Dense** (9+ transitions): O(1) lookup table worth the 1KB overhead
    fn classify_state_kind(&self) -> StateKind {
        match self.transitions.len() {
            0 => StateKind::Empty,
            1 => StateKind::One,
            2..=8 => StateKind::Sparse,
            _ => StateKind::Dense, // 9+ transitions
        }
    }
}

impl ACBuilder {
    fn new(mode: MatchMode) -> Self {
        Self {
            states: vec![BuilderState::new(0, 0)], // Root
            mode,
            patterns: Vec::new(),
        }
    }

    /// Add a pattern to the automaton
    ///
    /// # Case-Insensitive Mode
    ///
    /// For case-insensitive matching, patterns are normalized to lowercase here.
    /// This avoids the memory overhead of storing both uppercase and lowercase transitions.
    ///
    /// Example: Pattern "Hello" becomes "hello" with a single transition path,
    /// rather than 2^5 = 32 paths for all case combinations.
    fn add_pattern(&mut self, pattern: &str) -> Result<u32, ParaglobError> {
        let pattern_id = self.patterns.len() as u32;
        self.patterns.push(pattern.to_string());

        // For case-insensitive mode, normalize pattern to lowercase during build
        // We'll normalize text to lowercase during search instead of doubling transitions
        let pattern_bytes: Vec<u8> = match self.mode {
            MatchMode::CaseSensitive => pattern.as_bytes().to_vec(),
            MatchMode::CaseInsensitive => pattern.to_lowercase().into_bytes(),
        };

        // Build trie path
        let mut current = 0u32;
        let mut depth = 0u8;

        for &ch in &pattern_bytes {
            depth += 1;

            // Check if transition already exists
            if let Some(&next) = self.states[current as usize].transitions.get(&ch) {
                current = next;
            } else {
                // Create new state
                let new_id = self.states.len() as u32;
                self.states.push(BuilderState::new(new_id, depth));
                self.states[current as usize].transitions.insert(ch, new_id);
                current = new_id;
            }
        }

        // Add output
        self.states[current as usize].outputs.push(pattern_id);

        Ok(pattern_id)
    }

    fn build_failure_links(&mut self) {
        let mut queue = VecDeque::new();

        // Depth-1 states fail to root
        let root_children: Vec<u32> = self.states[0].transitions.values().copied().collect();

        for child in root_children {
            self.states[child as usize].failure = 0;
            queue.push_back(child);
        }

        // BFS to compute failure links
        while let Some(state_id) = queue.pop_front() {
            let transitions: Vec<(u8, u32)> = self.states[state_id as usize]
                .transitions
                .iter()
                .map(|(&ch, &next)| (ch, next))
                .collect();

            for (ch, next_state) in transitions {
                queue.push_back(next_state);

                // Find failure state
                let mut fail = self.states[state_id as usize].failure;
                let mut failure_found = false;

                // Follow failure links looking for a state with a transition for 'ch'
                while fail != 0 {
                    if let Some(&target) = self.states[fail as usize].transitions.get(&ch) {
                        self.states[next_state as usize].failure = target;
                        failure_found = true;
                        break;
                    }
                    fail = self.states[fail as usize].failure;
                }

                // If not found, check root
                if !failure_found {
                    if let Some(&target) = self.states[0].transitions.get(&ch) {
                        // Only set if target is not the node itself (avoid self-loop)
                        if target != next_state {
                            self.states[next_state as usize].failure = target;
                        } else {
                            self.states[next_state as usize].failure = 0;
                        }
                    } else {
                        self.states[next_state as usize].failure = 0;
                    }
                }

                // Merge outputs from ALL suffix states (via failure links)
                // This is critical: we need to inherit patterns from the entire failure link chain
                let mut suffix_state = self.states[next_state as usize].failure;
                while suffix_state != 0 {
                    let suffix_outputs = self.states[suffix_state as usize].outputs.clone();
                    if !suffix_outputs.is_empty() {
                        self.states[next_state as usize]
                            .outputs
                            .extend(suffix_outputs);
                    }
                    suffix_state = self.states[suffix_state as usize].failure;
                }
            }
        }
    }

    /// Serialize into offset-based format with state-specific encoding
    fn serialize(self) -> Result<Vec<u8>, ParaglobError> {
        let mut buffer = Vec::new();

        // Calculate section sizes - using cache-optimized ACNodeHot (16 bytes)
        let node_size = mem::size_of::<ACNodeHot>();
        let edge_size = mem::size_of::<ACEdge>();
        let dense_size = mem::size_of::<DenseLookup>();

        let nodes_start = 0;
        let nodes_size = self.states.len() * node_size;

        // Classify states and count by type
        let state_kinds: Vec<StateKind> = self
            .states
            .iter()
            .map(|s| s.classify_state_kind())
            .collect();

        let dense_count = state_kinds
            .iter()
            .filter(|&&k| k == StateKind::Dense)
            .count();
        let sparse_edges: usize = self
            .states
            .iter()
            .zip(&state_kinds)
            .filter(|(_, &kind)| kind == StateKind::Sparse)
            .map(|(s, _)| s.transitions.len())
            .sum();

        // ONE states don't need edge arrays!
        let total_patterns: usize = self.states.iter().map(|s| s.outputs.len()).sum();

        // Layout: [Nodes][Sparse Edges][Padding][Dense Lookups][Patterns]
        let edges_start = nodes_size;
        let edges_size = sparse_edges * edge_size;

        // Calculate padding to align dense section to 64-byte boundary
        // DenseLookup now has #[repr(C, align(64))] for cache-line alignment
        let unaligned_dense_start = edges_start + edges_size;
        let dense_alignment = mem::align_of::<DenseLookup>(); // 64 bytes
        let dense_padding =
            (dense_alignment - (unaligned_dense_start % dense_alignment)) % dense_alignment;
        let dense_start = unaligned_dense_start + dense_padding;
        let dense_size_total = dense_count * dense_size;

        let patterns_start = dense_start + dense_size_total;
        let patterns_size = total_patterns * mem::size_of::<u32>();

        // Calculate total size (including alignment padding)
        let total_size = nodes_size + edges_size + dense_padding + dense_size_total + patterns_size;

        // Reasonable size limit to prevent pathological inputs from causing OOM
        // Set to 2GB which is large enough for legitimate databases but catches
        // pathological inputs early
        const MAX_BUFFER_SIZE: usize = 2_000_000_000; // 2GB

        if total_size > MAX_BUFFER_SIZE {
            return Err(ParaglobError::ResourceLimitExceeded(format!(
                "Pattern database too large: {} bytes ({} states, {} sparse edges, {} dense, {} patterns). \
                     Maximum allowed is {} bytes. This may be caused by pathological patterns \
                     with many null bytes or special characters.",
                total_size,
                self.states.len(),
                sparse_edges,
                dense_count,
                total_patterns,
                MAX_BUFFER_SIZE
            )));
        }

        // Allocate buffer
        buffer.resize(total_size, 0);

        // Verify alignment of dense section
        debug_assert_eq!(
            dense_start % dense_alignment,
            0,
            "Dense section must be {}-byte aligned, but starts at offset {} ({}% alignment)",
            dense_alignment,
            dense_start,
            dense_start % dense_alignment
        );

        // Track offsets for writing data
        let mut edge_offset = edges_start;
        let mut dense_offset = dense_start;
        let mut pattern_offset = patterns_start;

        let node_offsets: Vec<usize> = (0..self.states.len())
            .map(|i| nodes_start + i * node_size)
            .collect();

        // Write each node with state-specific encoding
        for (i, state) in self.states.iter().enumerate() {
            let node_offset = node_offsets[i];
            let kind = state_kinds[i];

            // Prepare sorted edges for this state
            let mut edges: Vec<(u8, u32)> = state
                .transitions
                .iter()
                .map(|(&ch, &target)| (ch, node_offsets[target as usize] as u32))
                .collect();
            edges.sort_by_key(|(ch, _)| *ch); // Sort for efficient lookup

            // Write state-specific transition data
            let (edges_offset_for_node, one_char, _one_target) = match kind {
                StateKind::Empty => (0u32, 0u8, 0u32),

                StateKind::One => {
                    // Store single transition inline in node!
                    let (ch, target) = edges[0];
                    (target, ch, 0u32) // edges_offset stores target for ONE states
                }

                StateKind::Sparse => {
                    // Write edges to sparse edge array
                    let sparse_offset = edge_offset;

                    for (ch, target) in &edges {
                        let edge = ACEdge::new(*ch, *target);
                        unsafe {
                            let ptr = buffer.as_mut_ptr().add(edge_offset) as *mut ACEdge;
                            ptr.write(edge);
                        }
                        edge_offset += edge_size;
                    }

                    (sparse_offset as u32, 0u8, 0u32)
                }

                StateKind::Dense => {
                    // Write dense lookup table
                    let lookup_offset = dense_offset;
                    let mut lookup = DenseLookup {
                        targets: [0u32; 256],
                    };

                    for (ch, target) in &edges {
                        lookup.targets[*ch as usize] = *target;
                    }

                    unsafe {
                        let ptr = buffer.as_mut_ptr().add(dense_offset) as *mut DenseLookup;
                        ptr.write(lookup);
                    }
                    dense_offset += dense_size;

                    (lookup_offset as u32, 0u8, 0u32)
                }
            };

            // Write pattern IDs
            let patterns_offset_for_node = if state.outputs.is_empty() {
                0u32
            } else {
                pattern_offset as u32
            };

            for &pattern_id in &state.outputs {
                unsafe {
                    let ptr = buffer.as_mut_ptr().add(pattern_offset) as *mut u32;
                    ptr.write(pattern_id);
                }
                pattern_offset += mem::size_of::<u32>();
            }

            // Write cache-optimized hot node (16 bytes)
            let failure_offset = if state.failure == 0 {
                0
            } else {
                node_offsets[state.failure as usize]
            } as u32;

            // Validate counts fit in u8 (max 255)
            let edge_count_u8 = state.transitions.len().min(255) as u8;
            let pattern_count_u8 = state.outputs.len().min(255) as u8;

            // Create hot node with optimal field ordering for cache access
            let node = ACNodeHot {
                state_kind: kind as u8,
                one_char,
                edge_count: edge_count_u8,
                pattern_count: pattern_count_u8,
                edges_offset: edges_offset_for_node,
                failure_offset,
                patterns_offset: patterns_offset_for_node,
            };

            unsafe {
                let ptr = buffer.as_mut_ptr().add(node_offset) as *mut ACNodeHot;
                ptr.write(node);
            }
        }

        Ok(buffer)
    }
}

/// Offset-based Aho-Corasick automaton for building
///
/// All data is stored in a single byte buffer using offsets.
/// This struct is only used for building the automaton.
/// Querying is done via paraglob_offset's optimized implementation.
pub struct ACAutomaton {
    /// Binary buffer containing all automaton data
    buffer: Vec<u8>,
}

impl ACAutomaton {
    /// Create a new AC automaton (initially empty)
    pub fn new(_mode: MatchMode) -> Self {
        Self { buffer: Vec::new() }
    }

    /// Build the automaton from patterns
    ///
    /// This constructs the offset-based binary format directly.
    pub fn build(patterns: &[&str], mode: MatchMode) -> Result<Self, ParaglobError> {
        if patterns.is_empty() {
            return Err(ParaglobError::InvalidPattern(
                "No patterns provided".to_string(),
            ));
        }

        let mut builder = ACBuilder::new(mode);

        for pattern in patterns {
            if pattern.is_empty() {
                return Err(ParaglobError::InvalidPattern("Empty pattern".to_string()));
            }
            builder.add_pattern(pattern)?; // Propagate error
        }

        builder.build_failure_links();
        let buffer = builder.serialize()?;

        Ok(Self { buffer })
    }

    /// Get the buffer (for serialization)
    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_simple() {
        let patterns = vec!["he", "she", "his", "hers"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseSensitive).unwrap();

        assert!(!ac.buffer.is_empty());
    }
}

// Note: Query method tests removed - ACAutomaton is now only used for building.
// Querying is done via paraglob_offset's optimized inline implementation.
