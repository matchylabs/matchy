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
use zerocopy::Ref;

/// Prefetch memory into cache (cross-platform)
///
/// This is a hint to the CPU to load data into cache before it's needed.
/// Prefetching hides memory latency by loading data speculatively.
///
/// # Safety
///
/// The pointer must be valid (but doesn't need to be aligned or initialized).
/// Prefetch is always safe - it's just a hint that can be ignored.
#[inline(always)]
fn prefetch_read(ptr: *const u8) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_mm_prefetch(ptr as *const i8, core::arch::x86_64::_MM_HINT_T0);
    }
    
    #[cfg(target_arch = "aarch64")]
    unsafe {
        // ARM64 PRFM instruction: Prefetch for Load, Keep in L1 cache
        // PRFM PLDL1KEEP, [x0] - Prefetch for load into L1, temporal locality
        core::arch::asm!(
            "prfm pldl1keep, [{0}]",
            in(reg) ptr,
            options(nostack, preserves_flags, readonly)
        );
    }
    
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        // No-op on other architectures
        let _ = ptr;
    }
}

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

/// Offset-based Aho-Corasick automaton
///
/// All data is stored in a single byte buffer using offsets.
/// Can be used directly from memory or mmap'd files.
pub struct ACAutomaton {
    /// Binary buffer containing all automaton data
    buffer: Vec<u8>,
    /// Matching mode
    mode: MatchMode,
    /// Original patterns (needed for returning matches)
    patterns: Vec<String>,
    /// Cached root transition characters for fast-forward scanning
    /// Contains all characters that can start a match from the root node.
    /// Sorted and deduplicated for efficient SIMD scanning.
    root_transition_chars: Vec<u8>,
}

impl ACAutomaton {
    /// Create a new AC automaton (initially empty)
    pub fn new(mode: MatchMode) -> Self {
        Self {
            buffer: Vec::new(),
            mode,
            patterns: Vec::new(),
            root_transition_chars: Vec::new(),
        }
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

        let stored_patterns = builder.patterns.clone();
        let buffer = builder.serialize()?; // Propagate error

        // Extract root transition characters for fast-forward optimization
        let root_chars = Self::extract_root_chars(&buffer);

        Ok(Self {
            buffer,
            mode,
            patterns: stored_patterns,
            root_transition_chars: root_chars,
        })
    }

    /// Extract all characters that have transitions from the root node
    ///
    /// This is used for fast-forward optimization - we can skip to the next
    /// occurrence of any of these characters when we're at the root with no match.
    ///
    /// Returns a sorted, deduplicated vector of characters.
    fn extract_root_chars(buffer: &[u8]) -> Vec<u8> {
        let mut chars = Vec::new();

        if buffer.is_empty() {
            return chars;
        }

        // Read root node at offset 0
        let node_slice = match buffer.get(0..) {
            Some(s) => s,
            None => return chars,
        };

        let node_ref = match Ref::<_, ACNodeHot>::from_prefix(node_slice) {
            Ok((r, _)) => r,
            Err(_) => return chars,
        };
        let node = *node_ref;

        let kind = match StateKind::from_u8(node.state_kind) {
            Some(k) => k,
            None => return chars,
        };

        match kind {
            StateKind::Empty => {}

            StateKind::One => {
                chars.push(node.one_char);
            }

            StateKind::Sparse => {
                // Extract all edge characters
                let edges_offset = node.edges_offset as usize;
                let edge_size = mem::size_of::<ACEdge>();
                let count = node.edge_count as usize;

                for i in 0..count {
                    let edge_offset = edges_offset + i * edge_size;
                    if let Some(edge_slice) = buffer.get(edge_offset..) {
                        if let Ok((edge_ref, _)) = Ref::<_, ACEdge>::from_prefix(edge_slice) {
                            chars.push(edge_ref.character);
                        }
                    }
                }
            }

            StateKind::Dense => {
                // Extract all non-zero transitions from dense table
                let lookup_offset = node.edges_offset as usize;
                for ch in 0u8..=255 {
                    let target_offset_offset = lookup_offset + (ch as usize * 4);
                    if target_offset_offset + 4 <= buffer.len() {
                        let target = u32::from_le_bytes([
                            buffer[target_offset_offset],
                            buffer[target_offset_offset + 1],
                            buffer[target_offset_offset + 2],
                            buffer[target_offset_offset + 3],
                        ]);
                        if target != 0 {
                            chars.push(ch);
                        }
                    }
                }
            }
        }

        chars.sort_unstable();
        chars.dedup();
        chars
    }

    /// Fast-forward to the next potential match position
    ///
    /// Scans text looking for any character that can start a match from the root node.
    /// Uses SIMD automatically via the memchr crate (SSE2/AVX2/AVX-512 on x86_64, NEON on aarch64).
    ///
    /// # Performance
    ///
    /// - 1-3 root transitions: Uses memchr/memchr2/memchr3 (extremely fast, SIMD-accelerated)
    /// - 4-16 root transitions: Uses bit-parallel technique with potential auto-vectorization
    /// - 16+ root transitions: Returns current position (fast-forward not beneficial)
    ///
    /// # Returns
    ///
    /// - `Some(pos)`: Position of next character that could start a match
    /// - `None`: No possible matches in remaining text
    #[inline]
    fn fast_forward(&self, text: &[u8], start: usize) -> Option<usize> {
        use memchr::{memchr, memchr2, memchr3};

        if start >= text.len() {
            return None;
        }

        match self.root_transition_chars.len() {
            0 => None, // No patterns
            1 => {
                // Single character: use memchr (fastest path)
                memchr(self.root_transition_chars[0], &text[start..]).map(|offset| start + offset)
            }
            2 => {
                // Two characters: use memchr2
                memchr2(
                    self.root_transition_chars[0],
                    self.root_transition_chars[1],
                    &text[start..],
                )
                .map(|offset| start + offset)
            }
            3 => {
                // Three characters: use memchr3
                memchr3(
                    self.root_transition_chars[0],
                    self.root_transition_chars[1],
                    self.root_transition_chars[2],
                    &text[start..],
                )
                .map(|offset| start + offset)
            }
            4..=16 => {
                // 4-16 characters: use bit-parallel technique
                self.fast_forward_bitset(text, start)
            }
            _ => {
                // Many transitions from root - AC is already efficient without fast-forward
                Some(start)
            }
        }
    }

    /// Bit-parallel fast-forward for 4-16 root transitions
    ///
    /// Uses a 256-bit lookup table (32 bytes) to check membership.
    /// This loop often auto-vectorizes on modern compilers.
    #[inline]
    fn fast_forward_bitset(&self, text: &[u8], start: usize) -> Option<usize> {
        // Build 256-bit lookup table (one bit per ASCII value)
        let mut lookup = [0u8; 32];
        for &ch in &self.root_transition_chars {
            lookup[ch as usize / 8] |= 1 << (ch % 8);
        }

        // Branchless scan - compiler often vectorizes this
        for (i, &ch) in text[start..].iter().enumerate() {
            if (lookup[ch as usize / 8] & (1 << (ch % 8))) != 0 {
                return Some(start + i);
            }
        }
        None
    }

    /// Find all matches with their end positions
    ///
    /// Returns (end_position, pattern_id) for each match.
    /// The end_position is the byte offset immediately after the match.
    ///
    /// # Case-Insensitive Mode
    ///
    /// For case-insensitive matching, the caller MUST lowercase `text` before calling.
    /// Use `crate::simd_utils::ascii_lowercase()` for efficient conversion.
    pub fn find_with_positions(&self, text: &str) -> Vec<(usize, u32)> {
        self.find_with_positions_bytes(text.as_bytes())
    }

    /// Find all matches with their end positions (byte slice version)
    ///
    /// Returns (end_position, pattern_id) for each match.
    /// The end_position is the byte offset immediately after the match.
    ///
    /// # Case-Insensitive Mode
    ///
    /// For case-insensitive matching, the caller MUST lowercase `text_bytes` before calling.
    /// Use `crate::simd_utils::ascii_lowercase()` for efficient conversion.
    pub fn find_with_positions_bytes(&self, text_bytes: &[u8]) -> Vec<(usize, u32)> {
        if self.buffer.is_empty() {
            return Vec::new();
        }

        let mut matches = Vec::new();
        let mut current_offset = 0usize;

        // OPTIMIZATION: Skip to first potential match using fast-forward
        let mut pos = if let Some(first_pos) = self.fast_forward(text_bytes, 0) {
            first_pos
        } else {
            return matches; // No possible matches in entire text
        };

        while pos < text_bytes.len() {
            let ch = text_bytes[pos];
            let mut next_offset = self.find_transition(current_offset, ch);

            while next_offset.is_none() && current_offset != 0 {
                let node_slice = match self.buffer.get(current_offset..) {
                    Some(s) => s,
                    None => break,
                };
                let node_ref = match Ref::<_, ACNodeHot>::from_prefix(node_slice) {
                    Ok((r, _)) => r,
                    Err(_) => break,
                };
                let node = *node_ref;
                current_offset = node.failure_offset as usize;

                if current_offset == 0 {
                    break;
                }

                next_offset = self.find_transition(current_offset, ch);
            }

            if next_offset.is_none() {
                next_offset = self.find_transition(0, ch);
            }

            current_offset = next_offset.unwrap_or(0);

            // OPTIMIZATION: If we're back at root and no transition, fast-forward
            if current_offset == 0 && next_offset.is_none() {
                if let Some(next_pos) = self.fast_forward(text_bytes, pos + 1) {
                    pos = next_pos;
                    continue;
                } else {
                    break; // No more matches possible
                }
            }

            // Collect matches at this position (end pos is pos + 1)
            let node_slice = match self.buffer.get(current_offset..) {
                Some(s) => s,
                None => {
                    pos += 1;
                    continue;
                }
            };
            let node_ref = match Ref::<_, ACNodeHot>::from_prefix(node_slice) {
                Ok((r, _)) => r,
                Err(_) => {
                    pos += 1;
                    continue;
                }
            };
            let node = *node_ref;

            if node.pattern_count > 0 {
                let patterns_offset = node.patterns_offset as usize;
                let pattern_count = node.pattern_count as usize;

                if patterns_offset + pattern_count * 4 <= self.buffer.len() {
                    let pattern_slice = &self.buffer[patterns_offset..];
                    if let Ok((ids_ref, _)) =
                        Ref::<_, [u32]>::from_prefix_with_elems(pattern_slice, pattern_count)
                    {
                        for &pattern_id in ids_ref.iter() {
                            matches.push((pos + 1, pattern_id));
                        }
                    }
                }
            }

            pos += 1;
        }

        matches
    }

    /// Find all pattern IDs that match in the text
    ///
    /// This traverses the offset-based automaton directly.
    ///
    /// # Case-Insensitive Mode
    ///
    /// For case-insensitive matching, the caller MUST lowercase `text` before calling.
    /// Use `crate::simd_utils::ascii_lowercase()` for efficient conversion.
    pub fn find_pattern_ids(&self, text: &str) -> Vec<u32> {
        self.find_pattern_ids_bytes(text.as_bytes())
    }

    /// Find all pattern IDs that match in the text (byte slice version)
    ///
    /// This traverses the offset-based automaton directly.
    ///
    /// # Case-Insensitive Mode
    ///
    /// For case-insensitive matching, the caller MUST lowercase `text_bytes` before calling.
    /// Use `crate::simd_utils::ascii_lowercase()` for efficient conversion.
    pub fn find_pattern_ids_bytes(&self, text_bytes: &[u8]) -> Vec<u32> {
        if self.buffer.is_empty() {
            return Vec::new();
        }

        let mut pattern_ids = Vec::new();
        let mut current_offset = 0usize; // Root node

        // OPTIMIZATION: Skip to first potential match using fast-forward
        let mut pos = if let Some(first_pos) = self.fast_forward(text_bytes, 0) {
            first_pos
        } else {
            return pattern_ids; // No possible matches in entire text
        };

        while pos < text_bytes.len() {
            let ch = text_bytes[pos];

            // Try to find transition from current node
            let mut next_offset = self.find_transition(current_offset, ch);

            // Follow failure links until we find a transition or reach root
            while next_offset.is_none() && current_offset != 0 {
                let node_slice = match self.buffer.get(current_offset..) {
                    Some(s) => s,
                    None => break,
                };
                let node_ref = match Ref::<_, ACNodeHot>::from_prefix(node_slice) {
                    Ok((r, _)) => r,
                    Err(_) => break,
                };
                let node = *node_ref;
                current_offset = node.failure_offset as usize;

                if current_offset == 0 {
                    break;
                }

                next_offset = self.find_transition(current_offset, ch);
            }

            // If still no transition, try from root
            if next_offset.is_none() {
                next_offset = self.find_transition(0, ch);
            }

            // Update current position
            current_offset = next_offset.unwrap_or(0);

            // OPTIMIZATION: If we're back at root and no transition, fast-forward
            if current_offset == 0 && next_offset.is_none() {
                if let Some(next_pos) = self.fast_forward(text_bytes, pos + 1) {
                    pos = next_pos;
                    continue;
                } else {
                    break; // No more matches possible
                }
            }

            // Collect pattern IDs at this state
            // Note: Patterns from suffix states were already merged during build_failure_links
            let node_slice = match self.buffer.get(current_offset..) {
                Some(s) => s,
                None => {
                    pos += 1;
                    continue;
                }
            };
            let node_ref = match Ref::<_, ACNodeHot>::from_prefix(node_slice) {
                Ok((r, _)) => r,
                Err(_) => {
                    pos += 1;
                    continue;
                }
            };
            let node = *node_ref;
            if node.pattern_count > 0 {
                // Read pattern IDs with zerocopy (HOT PATH optimization)
                // Pattern IDs are always 4-byte aligned in our serialization format
                let patterns_offset = node.patterns_offset as usize;
                let pattern_count = node.pattern_count as usize;

                if patterns_offset + pattern_count * 4 <= self.buffer.len() {
                    let pattern_slice = &self.buffer[patterns_offset..];
                    if let Ok((ids_ref, _)) =
                        Ref::<_, [u32]>::from_prefix_with_elems(pattern_slice, pattern_count)
                    {
                        // Zero-copy path - direct slice access
                        pattern_ids.extend_from_slice(&ids_ref);
                    }
                }
            }

            pos += 1;
        }

        // Deduplicate and sort
        pattern_ids.sort_unstable();
        pattern_ids.dedup();
        pattern_ids
    }

    /// Find a transition from a node for a character
    ///
    /// Returns the offset to the target node, or None if no transition exists.
    ///
    /// # State-Specific Optimizations
    ///
    /// This is the HOTTEST path in pattern matching. We use different lookup strategies
    /// based on the state encoding:
    ///
    /// - **EMPTY**: No transitions, immediate return
    /// - **ONE** (75-80% of states): Single inline comparison, zero indirection!
    /// - **SPARSE**: Linear search through edge array (2-8 edges)
    /// - **DENSE**: O(1) lookup table access (9+ edges)
    ///
    /// The ONE encoding is the key optimization: by storing the single transition inline,
    /// we eliminate a cache miss that would occur when loading the edge array.
    ///
    /// # Cache Optimization
    ///
    /// Now using ACNodeHot (16 bytes) - fits 4 nodes per 64-byte cache line vs 2 previously.
    #[inline]
    fn find_transition(&self, node_offset: usize, ch: u8) -> Option<usize> {
        // Load hot node metadata (16 bytes - half the size of old ACNode)
        let node_slice = self.buffer.get(node_offset..)?;
        let (node_ref, _) = Ref::<_, ACNodeHot>::from_prefix(node_slice).ok()?;
        let node = *node_ref;

        // OPTIMIZATION: Prefetch failure link node speculatively
        // Failure links are followed frequently on mismatches, but unpredictably.
        // Prefetching hides the 40-200+ cycle memory latency.
        // This is free - if we don't need it, the prefetch is just ignored.
        if node.failure_offset != 0 && node.failure_offset < self.buffer.len() as u32 {
            prefetch_read(unsafe { self.buffer.as_ptr().add(node.failure_offset as usize) });
        }

        // Dispatch on state encoding
        let kind = StateKind::from_u8(node.state_kind)?;

        match kind {
            StateKind::Empty => {
                // No transitions
                None
            }

            StateKind::One => {
                // HOT PATH: Single inline comparison, no indirection!
                // This eliminates a cache miss for 75-80% of transitions
                if node.one_char == ch {
                    let target_offset = node.edges_offset as usize;
                    
                    // OPTIMIZATION: Prefetch target node - we'll need it next
                    if target_offset < self.buffer.len() {
                        prefetch_read(unsafe { self.buffer.as_ptr().add(target_offset) });
                    }
                    
                    Some(target_offset)
                } else {
                    None
                }
            }

            StateKind::Sparse => {
                // SIMD-accelerated search through sparse edge array (2-8 edges)
                let edges_offset = node.edges_offset as usize;
                let edge_size = mem::size_of::<ACEdge>();
                let count = node.edge_count as usize;

                // Pre-check: ensure all edges are in bounds
                let total_edge_bytes = count * edge_size;
                if edges_offset + total_edge_bytes > self.buffer.len() {
                    return None;
                }

                // Extract all edge characters into contiguous array for SIMD
                // This is cache-friendly and enables vectorized search
                let mut chars = [0u8; 8]; // Max 8 edges for sparse states
                for (i, char_slot) in chars.iter_mut().enumerate().take(count) {
                    let edge_offset = edges_offset + i * edge_size;
                    let edge_slice = &self.buffer[edge_offset..];
                    if let Ok((edge_ref, _)) = Ref::<_, ACEdge>::from_prefix(edge_slice) {
                        *char_slot = edge_ref.character;
                    } else {
                        return None; // Corrupted data
                    }
                }

                // SIMD search: check all characters at once (SSE2/AVX2)
                // For 2-8 bytes, this processes all in a single SIMD instruction
                if let Some(idx) = memchr::memchr(ch, &chars[..count]) {
                    // Found match at index - retrieve target offset
                    let edge_offset = edges_offset + idx * edge_size;
                    let edge_slice = &self.buffer[edge_offset..];
                    let (edge_ref, _) = Ref::<_, ACEdge>::from_prefix(edge_slice).ok()?;
                    let target_offset = edge_ref.target_offset as usize;
                    
                    // OPTIMIZATION: Prefetch target node - we'll need it next
                    if target_offset < self.buffer.len() {
                        prefetch_read(unsafe { self.buffer.as_ptr().add(target_offset) });
                    }
                    
                    return Some(target_offset);
                }

                None
            }

            StateKind::Dense => {
                // O(1) lookup in dense table (9+ edges)
                let lookup_offset = node.edges_offset as usize;
                let target_offset_offset = lookup_offset + (ch as usize * 4);

                // Bounds check
                if target_offset_offset + 4 > self.buffer.len() {
                    return None;
                }

                // Read target offset directly (4 bytes, little-endian)
                let target = u32::from_le_bytes([
                    self.buffer[target_offset_offset],
                    self.buffer[target_offset_offset + 1],
                    self.buffer[target_offset_offset + 2],
                    self.buffer[target_offset_offset + 3],
                ]);

                if target != 0 {
                    let target_offset = target as usize;
                    
                    // OPTIMIZATION: Prefetch target node - we'll need it next
                    if target_offset < self.buffer.len() {
                        prefetch_read(unsafe { self.buffer.as_ptr().add(target_offset) });
                    }
                    
                    Some(target_offset)
                } else {
                    None
                }
            }
        }
    }

    /// Get the buffer (for serialization)
    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    /// Get the patterns
    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }

    /// Get the match mode
    pub fn mode(&self) -> MatchMode {
        self.mode
    }

    /// Load from a buffer (for deserialization/mmap)
    pub fn from_buffer(
        buffer: Vec<u8>,
        patterns: Vec<String>,
        mode: MatchMode,
    ) -> Result<Self, ParaglobError> {
        // TODO: Validate buffer format

        // Extract root transition characters for fast-forward optimization
        let root_chars = Self::extract_root_chars(&buffer);

        Ok(Self {
            buffer,
            mode,
            patterns,
            root_transition_chars: root_chars,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_simple() {
        let patterns = vec!["he", "she", "his", "hers"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseSensitive).unwrap();

        assert_eq!(ac.patterns.len(), 4);
        assert!(!ac.buffer.is_empty());
    }

    #[test]
    fn test_find_pattern_ids() {
        let patterns = vec!["he", "she", "his", "hers"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseSensitive).unwrap();

        let ids = ac.find_pattern_ids("she sells his shells");
        assert!(!ids.is_empty());

        // Should find: "she" (id=1), "he" (id=0), "his" (id=2)
        assert!(ids.contains(&0)); // "he"
        assert!(ids.contains(&1)); // "she"
        assert!(ids.contains(&2)); // "his"
    }

    #[test]
    fn test_case_insensitive() {
        let patterns = vec!["Hello", "World"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseInsensitive).unwrap();

        let ids = ac.find_pattern_ids("hello world");
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&0));
        assert!(ids.contains(&1));
    }

    #[test]
    fn test_no_match() {
        let patterns = vec!["hello", "world"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseSensitive).unwrap();

        let ids = ac.find_pattern_ids("nothing here");
        assert!(ids.is_empty());
    }

    #[test]
    fn test_overlapping_patterns() {
        let patterns = vec!["test", "testing", "est"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseSensitive).unwrap();

        let ids = ac.find_pattern_ids("testing");
        assert_eq!(ids.len(), 3); // All three patterns match
    }

    #[test]
    fn test_fast_forward_single_pattern() {
        // Single pattern: fast-forward should use memchr
        let patterns = vec!["pattern"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseSensitive).unwrap();

        // Verify root transition chars extracted correctly
        assert_eq!(ac.root_transition_chars.len(), 1);
        assert_eq!(ac.root_transition_chars[0], b'p');

        // Test with sparse matches
        let text = "aaaaaaaaapattern bbbbbbbbbpattern ccccccccc";
        let ids = ac.find_pattern_ids(text);
        assert_eq!(ids.len(), 1);
        assert!(ids.contains(&0));

        // Test with positions
        let matches = ac.find_with_positions(text);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0], (16, 0)); // End of first "pattern"
        assert_eq!(matches[1], (33, 0)); // End of second "pattern"
    }

    #[test]
    fn test_fast_forward_two_patterns() {
        // Two patterns starting with different chars: fast-forward should use memchr2
        let patterns = vec!["apple", "banana"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseSensitive).unwrap();

        // Verify root transition chars
        assert_eq!(ac.root_transition_chars.len(), 2);
        assert!(ac.root_transition_chars.contains(&b'a'));
        assert!(ac.root_transition_chars.contains(&b'b'));

        // Test with text that should be skipped
        let text = "zzzzzzzzapplezzzzzzbananazzzzzz";
        let ids = ac.find_pattern_ids(text);
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&0)); // apple
        assert!(ids.contains(&1)); // banana
    }

    #[test]
    fn test_fast_forward_three_patterns() {
        // Three patterns: fast-forward should use memchr3
        let patterns = vec!["cat", "dog", "fish"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseSensitive).unwrap();

        // Verify root transition chars
        assert_eq!(ac.root_transition_chars.len(), 3);
        assert!(ac.root_transition_chars.contains(&b'c'));
        assert!(ac.root_transition_chars.contains(&b'd'));
        assert!(ac.root_transition_chars.contains(&b'f'));

        let text = "xxxcatxxxdogxxxfishxxx";
        let ids = ac.find_pattern_ids(text);
        assert_eq!(ids.len(), 3);
    }

    #[test]
    fn test_fast_forward_many_patterns() {
        // 4-16 patterns: should use bitset fast-forward
        let patterns = vec!["a1", "b2", "c3", "d4", "e5"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseSensitive).unwrap();

        // Verify root transition chars
        assert_eq!(ac.root_transition_chars.len(), 5);

        let text = "zzza1zzzb2zzzc3zzzd4zzze5zzz";
        let ids = ac.find_pattern_ids(text);
        assert_eq!(ids.len(), 5);
    }

    #[test]
    fn test_fast_forward_no_matches() {
        // Fast-forward should quickly determine no matches
        let patterns = vec!["pattern"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseSensitive).unwrap();

        let text = "abcdefghijklmnoxyz"; // No 'p' anywhere
        let ids = ac.find_pattern_ids(text);
        assert!(ids.is_empty());
    }

    #[test]
    fn test_fast_forward_match_at_start() {
        let patterns = vec!["start"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseSensitive).unwrap();

        let text = "start of the text";
        let ids = ac.find_pattern_ids(text);
        assert_eq!(ids.len(), 1);
        assert!(ids.contains(&0));
    }

    #[test]
    fn test_fast_forward_match_at_end() {
        let patterns = vec!["end"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseSensitive).unwrap();

        let text = "text finishes at the end";
        let ids = ac.find_pattern_ids(text);
        assert_eq!(ids.len(), 1);
        assert!(ids.contains(&0));
    }

    #[test]
    fn test_fast_forward_sparse_matches() {
        // Test with very sparse matches (fast-forward should shine here)
        let patterns = vec!["needle"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseSensitive).unwrap();

        // 1000 bytes with only 2 matches
        let mut text = String::new();
        for _ in 0..250 {
            text.push('x');
        }
        text.push_str("needle");
        for _ in 0..250 {
            text.push('y');
        }
        text.push_str("needle");
        for _ in 0..238 {
            text.push('z');
        }

        let ids = ac.find_pattern_ids(&text);
        assert_eq!(ids.len(), 1);
        assert!(ids.contains(&0));

        let matches = ac.find_with_positions(&text);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_fast_forward_dense_matches() {
        // Test with dense matches (fast-forward less beneficial but should still work)
        let patterns = vec!["a"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseSensitive).unwrap();

        let text = "aaaaaaaaaaaa";
        let ids = ac.find_pattern_ids(text);
        assert_eq!(ids.len(), 1);

        let matches = ac.find_with_positions(text);
        assert_eq!(matches.len(), 12); // Every 'a' matches
    }

    #[test]
    fn test_fast_forward_with_overlaps() {
        // Ensure fast-forward doesn't skip overlapping matches
        let patterns = vec!["aba", "bab"];
        let ac = ACAutomaton::build(&patterns, MatchMode::CaseSensitive).unwrap();

        let text = "abababa";
        let ids = ac.find_pattern_ids(text);
        assert_eq!(ids.len(), 2); // Both patterns should match
    }
}
