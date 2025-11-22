# Matchy - Developer Guide

This document covers architecture, implementation details, and performance characteristics for engineers working on or integrating with Matchy.

## What Matchy Does

Matchy is a unified database for IP address and pattern matching. Single file format, single query API. You build a database with IPs (including CIDRs), exact strings, and glob patterns, then query it with anything—IP addresses, domain names, file paths, whatever. The system figures out what you're looking for and returns results in microseconds.

Key capabilities:
- **IP lookups**: Binary trie, sub-microsecond queries
- **Exact string matching**: Hash table, O(1) lookups
- **Glob pattern matching**: Aho-Corasick + glob engine, performance varies by pattern complexity
- **Zero-copy mmap**: Database loads in ~1ms regardless of size, shared across processes
- **Rich metadata**: JSON-like structured data attached to each entry
- **MMDB compatibility**: Extended MaxMind format, works with existing tooling

## Architecture Overview

### File Format

Matchy extends the MaxMind DB (MMDB) binary format. An `.mxy` file is a valid MMDB file with an additional embedded section for patterns:

```
┌────────────────────────────────────┐
│  IP Search Tree (binary trie)      │  ← IPv4/IPv6 addresses
├────────────────────────────────────┤
│  Data Section (deduplicated)       │  ← JSON-like structured data
├────────────────────────────────────┤
│  PARAGLOB Section (optional)       │  ← Glob patterns
│    - AC nodes/edges                │     (Aho-Corasick + glob engine)
├────────────────────────────────────┤
│  Literal Hash Section (optional)   │  ← Exact string matching
│    - Hash table (XXH64)            │
├────────────────────────────────────┤
│  MMDB Metadata (last 128KB)        │  ← Binary format info,
│                                    │     section offsets
└────────────────────────────────────┘
```

**Why this works**: MMDB format includes a metadata section that can hold arbitrary key-value pairs. Matchy stores the offset and size of the PARAGLOB section there. Standard MMDB readers ignore it and just use the IP tree. Matchy reads both.

### Query Path

When you call `db.lookup("something")`:

1. **Detection**: Is it an IP address?
   - Attempt to parse as IPv4/IPv6
   - If successful → search IP tree (binary trie)
   - Return immediately if found

2. **Literal match**: Check exact string hash table
   - O(1) lookup using XXH64
   - Common for domain blocklists with exact matches
   - Return if found

3. **Glob match**: Run Aho-Corasick
   - Scan input for literals extracted from glob patterns
   - For each AC match, verify with glob engine
   - Return all matching globs

4. **Cache**: Results cached in LRU (optional, enabled via `DatabaseOpener::cache_capacity()`)

### Module Organization

50 source files, ~13K SLOC. Key modules:

**Core Query Engine**:
- `database.rs` (47K) - Main `Database` struct, unified query API, result caching
- `paraglob_offset.rs` (74K) - Glob matching engine (AC + glob)
- `ac_offset.rs` (46K) - Offset-based Aho-Corasick automaton for mmap
- `glob.rs` (25K) - Glob matching (wildcards, character classes)
- `literal_hash.rs` (24K) - Exact string matching via hash table
- `ac_literal_hash.rs` (13K) - Literal-to-glob-ID mapping

**Database Construction**:
- `mmdb_builder.rs` (35K) - Unified builder (`DatabaseBuilder`), entry type detection
- `ip_tree_builder.rs` (23K) - Binary trie builder for IP addresses
- `data_section.rs` (49K) - Data encoding/deduplication

**Binary Format**:
- `offset_format.rs` (28K) - `#[repr(C)]` structures for PARAGLOB section
- `mmdb/` - MMDB format reading/writing (internal)
- `endian.rs` (9K) - Cross-platform byte order handling
- `serialization.rs` (8K) - High-level save/load/mmap API

**Data Extraction & Processing**:
- `extractor.rs` (118K) - SIMD-accelerated extraction of IPs, domains, emails, crypto addresses
- `processing.rs` (62K) - Batch processing infrastructure (Worker, LineFileReader, stats)
- `file_reader.rs` (6K) - Streaming I/O with gzip support

**Utilities & Safety**:
- `validation.rs` (110K) - Comprehensive database validation (untrusted files)
- `mmap.rs` (12K) - Memory-mapped file wrapper
- `error.rs` (2K) - Error types
- `simd_utils.rs` (9K) - SIMD acceleration helpers

**FFI**:
- `c_api/matchy.rs` - Native C API (opaque handles)
- `c_api/maxminddb_compat.rs` - MaxMind-compatible C API

**Build & CLI**:
- `bin/` (26 files) - CLI implementation (`matchy build`, `match`, `query`, etc.)

### Data Structure Design

**Offset-based, not pointer-based**: Everything uses file offsets (u32/u64) instead of pointers. This is critical for mmap:

```rust
// ❌ Won't work with mmap (pointers invalid after load)
struct Node {
    next: *const Node,
}

// ✅ Works with mmap (offset into mapped region)
#[repr(C)]
struct Node {
    next_offset: u32,
}
```

At query time, we add the offset to the base address of the mapped region. Validated at load time to prevent out-of-bounds access.

**Why `#[repr(C)]`**: Guarantees stable field layout across Rust versions and platforms. Required for binary format compatibility.

## Performance Characteristics

Performance varies significantly based on query type, database size, and glob pattern complexity. General behaviors:

### IP Lookups

**Algorithm**: Binary trie traversal, depth = address bit length (max 128 bits for IPv6).

**Scaling**: Near-constant time regardless of database size. Adding 10× more IPs has minimal impact on query latency.

**Database size**: Compact. ~6 bytes per IP for just the tree structure, plus data storage.

**Build time**: Fast and scales linearly. Databases with 100K+ IPs build in milliseconds.

**Notes**:
- IPv4-only databases use 32-bit address space for efficiency
- IPv6 databases use 128-bit address space (can include IPv4-mapped addresses)
- Tree depth auto-selected based on addresses present in database
- CIDR ranges supported via prefix matching
- Load time ~1ms via mmap regardless of DB size

### Exact String Matching

**Algorithm**: XXH64 hash table, O(1) expected case.

**Scaling**: Performance stays good up to ~50K entries. At larger scales, lookup time increases due to longer probe chains in the hash table (uses linear probing with 0.8 load factor). Still usable at 100K+ entries but noticeably slower than small tables.

**Database size**: ~50-100 bytes per entry (depends on string length and hash distribution).

**Build time**: Fast, scales linearly. Build-time deduplication removes identical strings automatically.

**Use case**: Exact domain/URL/path matching before falling back to glob matching.

### Glob Matching

Performance varies **dramatically** based on glob complexity. Not all globs are created equal.

**How it works**:
1. Extract literals from each glob at build time (e.g., "evil.com" from `*.evil.com`)
2. Build Aho-Corasick automaton from extracted literals
3. At query time: scan input with AC, then verify full glob match for each AC hit

**Pattern complexity hierarchy** (fastest to slowest):

1. **Suffix patterns** (`*.evil.com`, `*.log`)
   - Fastest: AC finds literal, verify it's at end of string
   - Scales well even with tens of thousands of globs
   - Recommended for domain blocklists

2. **Prefix patterns** (`error-*`, `temp_*`)
   - Moderate: AC finds literal, verify it's at start
   - Scales reasonably well
   - Recommended for log files, file matching

3. **Mixed simple** (`prefix-*.suffix`)
   - Moderate: AC finds one literal, glob verifies both ends
   - Performance depends on literal uniqueness

4. **Complex patterns** (`*[0-9][0-9]*.evil.*`)
   - Slow: Multiple wildcards trigger extensive backtracking
   - Performance degrades severely with scale (10-100× slower than suffix)
   - Each AC match requires expensive glob verification

**Why the huge difference?** 

Suffix pattern `*.evil.com`: The literal "evil.com" uniquely identifies the glob. After AC matches, one suffix check and we're done. Simple, fast, scales.

Complex pattern `*[0-9][0-9]*.evil.*`: Might extract 10+ literals. Each AC match triggers recursive backtracking through the glob engine. At high scale, you're doing thousands of expensive glob matches per query.

**Recommendation**: Keep globs simple. If you have `*[0-9][0-9].evil.com`, consider exploding it to 100 concrete globs (`*00.evil.com` through `*99.evil.com`). Build time increases slightly, query time drops 10-100×.

### Build & Load Times

**Build**: Fast and scales linearly with entry count. Databases with 100K entries typically build in tens of milliseconds. Complex globs take longer to build than simple globs due to literal extraction overhead.

**Load**: Memory-mapped via single `mmap()` syscall, typically <1ms regardless of database size. No deserialization, no copies. OS pages in data on-demand.

**Memory efficiency in multi-process setups**:

Traditional approach (heap deserialization): Each process loads its own copy. 50 workers × 100 MB database = 5,000 MB RAM.

Matchy approach (mmap): OS shares physical pages across processes. 50 workers reading same file = 100 MB RAM total. **98% savings**.

## Implementation Notes

### Test Coverage

**242 tests passing** (as of latest run). Coverage includes:
- Unit tests in each module
- Integration tests for end-to-end workflows
- Property-based tests for glob matching edge cases
- Round-trip serialization tests
- CLI integration tests via `assert_cmd`

### Glob Engine

Supports standard glob syntax:
- `*` - matches any sequence (including empty)
- `?` - matches exactly one character
- `[abc]` - character class (matches a, b, or c)
- `[!abc]` or `[^abc]` - negated character class
- `[a-z]` - range syntax

**Implementation**: Recursive backtracking matcher with step limit to prevent pathological cases. Fast for simple globs where wildcards have few choices. Slow for complex globs with multiple wildcards that generate many backtracking paths. This is why suffix/prefix globs outperform complex globs by 100×+.

### Aho-Corasick Automaton

Classic AC implementation with failure links:
1. Build a trie from pattern literals
2. Compute failure links (BFS from root)
3. At query time, traverse based on input, following failure links on mismatch

**Critical fix** (historical): Original implementation broke after following a failure link, preventing detection of overlapping matches. Fixed by continuing the loop after failure transitions.

### Data Deduplication

The data section deduplicates identical metadata across entries. If 1000 IPs all have `{"threat_level": "high"}`, we store it once and reference it 1000 times. Implemented via content-addressed storage (hash the data, check for existing entry).

Typical compression: 50-80% for threat feeds with similar metadata.

### FFI Design

Two C APIs provided:
1. **Native API** (`matchy_*` functions) - Full Matchy functionality
2. **MaxMind-compatible API** (`MMDB_*` functions) - Drop-in replacement for libmaxminddb

Both use opaque handles and return error codes. All string data passed as `const char*` with explicit lengths. No C++ exceptions across FFI boundary.

**Panic safety**: All `extern "C"` functions wrapped in `catch_unwind()`. Panics convert to error codes rather than aborting.

## Data Extraction

The `extractor` module finds structured data in unstructured text: IPs, domains, emails, file hashes, crypto addresses.

**Supported types**:
- **IPv4/IPv6**: Standard address formats
- **Domains**: Validated against Public Suffix List (PSL)
- **Emails**: RFC-like validation with PSL TLD checks
- **File hashes**: MD5, SHA1, SHA256, SHA384 (hex, length-based detection)
- **Crypto addresses**: Bitcoin (Base58Check + Bech32), Ethereum (EIP-55), Monero (Keccak256)

**Performance**: ~450 MB/s single-threaded. Uses SIMD via `memchr` for anchor detection (dots, @, 0x prefix). Expands boundaries, validates checksums where applicable.

**Usage**:
```rust
let extractor = Extractor::new()?;
for item in extractor.extract_from_line(log_line.as_bytes()) {
    // item.text, item.match_type
}
```

## Batch Processing

The `processing` module provides infrastructure for scanning files against databases:

**Key types**:
- `LineFileReader` - Streams file in chunks, handles gzip automatically
- `Worker` - Combines extractor + database(s), processes batches
- `LineMatch` - Match result with file/line context
- `WorkerStats` - Accumulates processing statistics

**Multi-database support**: One `Worker` can query multiple databases. Useful for cross-referencing threat feeds and allowlists.

```rust
let mut worker = processing::Worker::builder()
    .extractor(extractor)
    .add_database("threats", threat_db)
    .add_database("allow", allow_db)
    .build();

let reader = processing::LineFileReader::new("log.gz", 128 * 1024)?;
for batch in reader.batches() {
    for match_item in worker.process_lines(&batch?)? {
        println!("{}:{} - {} in {}",
            match_item.source.display(),
            match_item.line_number,
            match_item.match_result.matched_text,
            match_item.match_result.database_id);
    }
}
```

## Database Validation

For untrusted databases, use validation before loading:

**Three levels**:
1. **Basic** (~1ms): Magic bytes, version, critical offsets
2. **Standard** (~5ms): All offsets, UTF-8, structure integrity
3. **Strict** (~10ms): Graph analysis, cycle detection, efficiency warnings

**What's checked**:
- Binary format integrity
- Offset bounds (prevent out-of-bounds reads)
- UTF-8 validity of all strings
- AC automaton structure (no cycles in failure links)
- Data section consistency

**CLI**:
```bash
matchy validate untrusted.mxy --level strict
```

**API**:
```rust
use matchy::validation::{validate_database, ValidationLevel};

let report = validate_database(
    Path::new("db.mxy"),
    ValidationLevel::Standard
)?;

if !report.is_valid() {
    return Err("Validation failed");
}
```

Database loading always validates UTF-8 on string reads for safety. There is no "trusted mode" that skips validation.

## Future Optimizations

Current performance is good for most use cases. If you need more:

### 1. Glob-Specific Data Structures

**Problem**: All globs go through AC + glob verification, even simple ones.

**Solution**: Detect glob types at build time, route to specialized structures:
- **Suffix globs** (`*.evil.com`) → reverse suffix trie
- **Prefix globs** (`error-*`) → prefix trie
- **Exact strings** already use hash table (fast)
- **Complex globs** → keep using AC + glob engine (no better alternative)

**Impact**: Potentially 2-3× speedup for workloads dominated by suffix/prefix globs.

**Effort**: Medium. Would require new binary format sections.

### 2. Query Result Caching

**Already implemented**: `DatabaseOpener::cache_capacity(n)` enables LRU cache.

**Impact**: 2-10× speedup for high-traffic scenarios with query repetition (web servers, DNS filtering).

**No code changes needed** - just use the API.

### 3. Glob Simplification

**Problem**: Complex globs (`*[0-9][0-9].evil.com`) are slow due to recursive backtracking in glob engine.

**Solution**: Explode to concrete globs (`*00.evil.com`, `*01.evil.com`, ..., `*99.evil.com`).

**Impact**: Build time increases slightly, query time can drop 10-100×.

**When to do this**: If you have complex globs and query performance matters more than build time.

## Building & Testing

See [WARP.md](WARP.md) for complete development workflow. Quick reference:

```bash
# Development
cargo build
cargo test
cargo clippy
cargo fmt

# Release
cargo build --release
cargo bench

# Documentation
cargo doc --no-deps --open
cd book && mdbook serve  # User guide
```

## Additional Documentation

- **README.md** - Project overview, quick start, features
- **WARP.md** - Complete development guide (workflow, best practices, module details)
- **book/** - User documentation (mdbook)
- **examples/** - Working code examples
- **Cargo docs** - API reference (`cargo doc --open`)

## Summary

Matchy is a production-ready unified database for IP addresses and glob matching. Key architectural decisions:

1. **Extended MMDB format** - Backward compatible, standards-based
2. **Offset-based structures** - Enable zero-copy mmap with shared memory
3. **Unified query API** - Automatic detection (IP vs string vs glob)
4. **Multiple data structures** - Binary trie (IPs), hash table (literals), AC+glob engine
5. **Safety first** - UTF-8 validation, comprehensive validation module

Performance is excellent for typical workloads. Glob performance varies dramatically by complexity - keep globs simple when possible. Multi-process deployments benefit massively from mmap (98% memory savings).

242 tests passing. Ready for production use.
