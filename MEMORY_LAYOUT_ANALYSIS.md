# Memory Layout Optimization Analysis

## Current Layout

```
[ACNodeHot array (contiguous)]
  - 16 bytes per node
  - 4 nodes per 64-byte cache line
  - Sequential by node ID

[Sparse Edge arrays (scattered)]
  - 8 bytes per edge (character + target offset)
  - Different states' edges are adjacent
  - Not aligned to cache lines

[Padding for alignment]

[Dense Lookup tables (aligned)]
  - 1024 bytes per table
  - 64-byte aligned (cache line boundary)
  - Only for states with 9+ transitions

[Pattern ID arrays (scattered)]
  - 4 bytes per pattern ID
  - Not cache-aligned
```

## Current Cache Behavior

### Good:
✅ **ACNodeHot is 16 bytes** - 4 nodes per cache line
✅ **Dense lookups are 64-byte aligned** - no cache line splits
✅ **Sequential node access** - prefetcher-friendly for trie traversal

### Problems:
❌ **Sparse edges are scattered** - each state's edges in different locations
❌ **Failure links jump randomly** - poor spatial locality
❌ **Pattern IDs are scattered** - separate cache miss to collect matches
❌ **No prefetching** - CPU doesn't know what to load next

## Cache Miss Analysis

For a typical AC transition:

```rust
// 1. Load current node (16 bytes)
let node = *node_ref;  // Usually cache hit (sequential access)

// 2. Check state kind, dispatch
// For SPARSE states:

// 3. Load edge array (2-8 edges × 8 bytes = 16-64 bytes)
let edge_slice = &self.buffer[edges_offset..];  // CACHE MISS #1
// Edges might not be in same cache line as node!

// 4. On match, load target node
let next_node_offset = edge_ref.target_offset;  // Offset calculated
// Target node might be far away in memory

// 5. If at match position, load pattern IDs
let pattern_slice = &self.buffer[patterns_offset..];  // CACHE MISS #2
```

**Estimated cache misses per transition**: 1-2
**On modern CPU** (3-4 cycles for L1, 12 cycles for L2, 40+ for L3, 200+ for RAM)

## Optimization Opportunities (Ranked)

### 1. **HIGH IMPACT: Prefetch Failure Link Nodes**
**Why**: Failure links are followed frequently, but unpredictably

**Implementation**:
```rust
// In find_transition(), after loading current node:
let node = *node_ref;

// Speculatively prefetch failure node into cache
if node.failure_offset != 0 {
    unsafe {
        core::arch::x86_64::_mm_prefetch(
            self.buffer.as_ptr().add(node.failure_offset as usize) as *const i8,
            core::arch::x86_64::_MM_HINT_T0  // L1 cache
        );
    }
}
```

**Expected impact**: 10-30% speedup on workloads with frequent failure transitions
**Complexity**: LOW - just add prefetch intrinsics
**Risk**: LOW - prefetch is a hint, can't break correctness

---

### 2. **HIGH IMPACT: Interleave Sparse Edges with Nodes**
**Why**: Sparse edges are accessed immediately after loading node

**Current layout**:
```
[All nodes][All sparse edges][Dense tables][Patterns]
```

**Optimized layout**:
```
[Node 0][Edges for Node 0 (if sparse)]
[Node 1][Edges for Node 1 (if sparse)]
[Node 2][Edges for Node 2 (if sparse)]
...
[Dense tables][Patterns]
```

**Benefits**:
- Edges in same/adjacent cache line as parent node
- Eliminates most edge-loading cache misses
- Still maintains sequential node array for traversal

**Expected impact**: 15-25% speedup for workloads heavy on sparse states
**Complexity**: MEDIUM - requires changing serialization format
**Risk**: MEDIUM - format version bump, need migration

---

### 3. **MEDIUM IMPACT: Prefetch Target Node**
**Why**: After finding a matching transition, we need the target node

**Implementation**:
```rust
// After finding transition match in SPARSE/DENSE:
let target_offset = edge_ref.target_offset as usize;

// Prefetch target node before returning
unsafe {
    core::arch::x86_64::_mm_prefetch(
        self.buffer.as_ptr().add(target_offset) as *const i8,
        core::arch::x86_64::_MM_HINT_T0
    );
}

Some(target_offset)
```

**Expected impact**: 5-15% speedup
**Complexity**: LOW
**Risk**: LOW

---

### 4. **MEDIUM IMPACT: Align Sparse Edges to 8-byte Boundaries**
**Why**: ACEdge is 8 bytes; misaligned loads are slower

**Current**: Edges are written sequentially, alignment not guaranteed
**Optimized**: Ensure each state's edge array starts on 8-byte boundary

**Expected impact**: 3-8% speedup
**Complexity**: LOW - add padding during serialization
**Risk**: LOW - slightly increases file size

---

### 5. **LOW-MEDIUM IMPACT: Pack Hot Metadata Together**
**Why**: Group frequently-accessed data in first cache line

**Current ACNodeHot** (16 bytes, already good):
```rust
state_kind(1) + one_char(1) + edge_count(1) + pattern_count(1)  // 4 bytes
edges_offset(4) + failure_offset(4) + patterns_offset(4)        // 12 bytes
```

**Could reorganize to**:
```rust
// First 8 bytes: Everything needed for transition lookup
state_kind(1) + one_char(1) + edge_count(1) + _pad(1) + edges_offset(4)

// Second 8 bytes: Less frequently accessed
failure_offset(4) + pattern_count(1) + _pad(3)
```

But this is marginal since whole node fits in single cache line anyway.

**Expected impact**: 1-3% speedup
**Complexity**: LOW
**Risk**: LOW

---

### 6. **LOW IMPACT: Use Huge Pages for Large Databases**
**Why**: Reduces TLB misses for large memory-mapped files

**Implementation**: `madvise(MADV_HUGEPAGE)` on mmap'd regions

**Expected impact**: 2-5% speedup on very large databases (100MB+)
**Complexity**: LOW
**Risk**: LOW - platform-specific

## Recommended Implementation Order

### Phase 1: Prefetching (Quick Wins)
1. Prefetch failure link nodes
2. Prefetch target nodes after transition
**Time**: 2-3 hours
**Expected gain**: 15-40% combined

### Phase 2: Edge Alignment
3. Align sparse edges to 8-byte boundaries
**Time**: 1-2 hours  
**Expected gain**: 3-8% additional

### Phase 3: Layout Redesign (Big Win, More Work)
4. Interleave edges with nodes
**Time**: 1-2 days (format change, migration, testing)
**Expected gain**: 15-25% additional

### Phase 4: Advanced
5. Huge page support
6. Further metadata packing experiments

## Measurement Strategy

For each optimization:

1. **Microbenchmark**: Isolated `find_transition` calls
2. **Full benchmark**: `cargo bench --bench matchy_bench`
3. **Cache profiling**: Use `perf stat -e cache-misses,cache-references` on Linux
4. **Mac profiling**: Use Instruments (Time Profiler, System Trace)

## Expected Total Gains

Conservative estimate combining Phase 1-3:
- **Best case**: 40-60% speedup (if cache misses are dominant)
- **Likely case**: 25-40% speedup
- **Worst case**: 15-25% speedup (if already memory-bound)

This is **much higher** than the ~4% from branch optimization, because:
- Cache miss penalty (40-200+ cycles) >> branch misprediction penalty (10-20 cycles)
- Current code has ~1-2 cache misses per transition
- Eliminating even one cache miss per transition is huge

## Next Steps

Want to implement Phase 1 (prefetching)? It's low-risk, high-reward, and should show results quickly!
