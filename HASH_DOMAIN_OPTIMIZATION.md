# Hash-Based Domain Extraction Optimization

## Summary

Replaced Aho-Corasick automaton (16K patterns) with hash-based PSL lookup for domain TLD validation, achieving **3-5.5x speedup** on typical workloads.

## Changes Made

### 1. Hash-Based PSL Lookup (src/extractor.rs)

**Before**: 
- Used AC automaton with 16K TLD patterns
- Scanned entire chunk with `find_matches_with_positions_bytes_into()`
- O(chunk_len × num_patterns) complexity

**After**:
- Parse PSL at compile time into `HashSet<&'static str>`
- Find dots with memchr (SIMD), extract candidates around each dot
- Validate TLD with O(1) hash lookup
- Walk backwards through dots to find longest suffix match

```rust
// Old approach (AC-based)
tld_matcher.find_matches_with_positions_bytes_into(chunk, &mut tld_buffer);
// Scans entire chunk with 16K patterns

// New approach (hash-based)
for dot_pos in memchr_iter(b'.', chunk) {
    // Extract candidate around dot
    let candidate = extract_domain_candidate(chunk, dot_pos);
    
    // Validate TLD with hash lookup - O(1)
    if let Some(tld_start) = find_valid_tld_suffix(candidate) {
        // Valid domain!
    }
}
```

### 2. Shared Dot Preprocessing

Added pre-computed dot positions shared between IPv4 and domain extraction:

```rust
// In extract_from_chunk()
let dot_positions = if self.extract_ipv4 || self.extract_domains {
    let mut buf = self.dot_positions_buffer.borrow_mut();
    buf.clear();
    buf.extend(memchr::memchr_iter(b'.', chunk));
    Some(buf)
} else {
    None
};

// Both extractors use the same dot positions
self.extract_ipv4_chunk_with_dots(chunk, &mut matches, dots_ref);
self.extract_domains_chunk_with_dots(chunk, &mut matches, dots_ref);
```

**Benefits**:
- Single memchr scan instead of two
- Eliminates redundant work when both IPv4 and domains enabled
- Similar pattern to existing word boundary preprocessing

## Performance Results

### Benchmark Comparison

| Workload | Before | After | Speedup |
|----------|--------|-------|---------|
| **100KB low-density** | 422µs (224 MiB/s) | 77µs (1.2 GiB/s) | **5.5x** |
| **100KB high-density** | 661µs (144 MiB/s) | 466µs (204 MiB/s) | **1.4x** |
| **Realistic logs (1000 lines)** | 314µs (224 MiB/s) | 103µs (683 MiB/s) | **3.0x** |

### Why the Speedup?

**Low-density workloads** (few domains):
- AC scans entire chunk with 16K patterns regardless of content
- Hash approach only works on dots (sparse in low-density data)
- **Result**: 5.5x speedup by avoiding unnecessary work

**High-density workloads** (many domains):
- More dots means more candidates to process
- Validation/deduplication still needed per domain
- **Result**: 1.4x speedup from faster TLD validation

**Realistic logs** (typical production):
- Mix of domains, IPs, and other content
- Benefits from both dot preprocessing and hash lookups
- **Result**: 3x speedup

### Expected Production Impact

From earlier profiling:
- **Before**: 26.38s extraction time (70% of CPU)
- **Expected after**: 8-13s extraction time (3-5x speedup)
- **Lookups**: 0.00s (unchanged - still instant)

## Algorithm Details

### find_valid_tld_suffix()

Walks backwards through dots, checking each suffix against PSL:

```
Input: "foo.bar.co.uk"

Step 1: Find last dot at position 10 (".uk")
  Check "uk" in PSL? Yes, but continue...
  
Step 2: Find previous dot at position 7 (".co.uk")
  Check "co.uk" in PSL? Yes! Return 7

Result: TLD starts at position 7 (".co.uk")
```

**Why longest-match?**  
PSL rules require longest suffix match. For example:
- "example.co.uk" → TLD is ".co.uk" (not just ".uk")
- "example.uk" → TLD is ".uk"

### Domain Extraction Flow

1. **Pre-filter**: memchr finds all dots in chunk (SIMD-fast)
2. **Candidate extraction**: For each dot, scan backwards/forwards to find domain boundaries
3. **Deduplication**: HashSet tracks seen domain spans (avoid duplicates from multiple dots)
4. **TLD validation**: hash lookup in PSL (O(1))
5. **Domain validation**: Check label format, count, boundaries

## Test Results

All 79 tests pass:
```
test result: ok. 79 passed; 0 failed; 0 ignored; 0 measured
```

Including domain-specific tests:
- Multi-label domains (example.co.uk)
- International domains (IDN)
- Edge cases (bare TLDs, invalid chars)
- Word boundary validation

## Code Cleanup

Removed unused code after migration:
- `expand_domain_backwards()` - replaced by direct candidate extraction
- AC-based domain extraction logic
- Unused `last_dot` variable in `find_valid_tld_suffix()`

## Future Optimizations

Potential further improvements:
1. **SIMD candidate extraction**: Vectorize backwards/forwards scanning
2. **Perfect hash function**: Replace `HashSet` with perfect hash for PSL (compile-time generation)
3. **Batch validation**: Process multiple domains before hash lookups (cache locality)

## Files Modified

- `src/extractor.rs`:
  - Added `dot_positions_buffer` field to `Extractor`
  - Added `PSL_SUFFIXES` static hash set
  - Added `find_valid_tld_suffix()` function
  - Replaced `extract_domains_chunk()` with `extract_domains_chunk_with_dots()`
  - Updated `extract_ipv4_chunk()` to `extract_ipv4_chunk_with_dots()`
  - Updated `extract_from_chunk()` to pre-compute dot positions
  - Removed `expand_domain_backwards()` (unused)

## Backward Compatibility

✅ **Fully compatible**:
- Same public API (`Extractor::new()`, `extract_from_chunk()`, etc.)
- Same extraction results (all tests pass)
- Same PSL data (just different data structure)
- TLD automaton still embedded (unused but available for future use)
