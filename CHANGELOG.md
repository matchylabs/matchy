# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.0] - 2025-11-23

### Added
- **Lock-Free Auto-Reload** with zero-overhead database access
  - Automatic database reloading when file changes are detected
  - Lock-free Arc swapping using `arc-swap` crate for atomic database updates
  - Thread-local Arc caching eliminates atomic operations on hot query path
  - Per-query overhead: ~1-2ns (atomic generation counter check only)
  - Enable with `Database::from(path).auto_reload().open()`
  - Graceful database handoff: old database stays alive until all threads finish with it
  - 200ms debounce prevents rapid reload cycles during file writes
  - File watching works with atomic renames (e.g., `mv new.mxy db.mxy`)
  - Scales to 160+ cores without lock contention or cache line ping-ponging
  
- **Reload Callbacks** for database change notifications (Rust + C API)
  - Rust API: `.on_reload()` method accepts closures for reload events
  - C API: `reload_callback` function pointer in `matchy_open_options_t`
  - Callback receives: file path, success status, error message (if failed), generation counter
  - Invoked from watcher thread on both successful and failed reloads
  - Useful for logging, metrics, and coordinating application state
  - Thread-safe callback execution with proper error handling
  - Examples: `examples/c_reload_callback.c`, Rust test in `src/database.rs`

### Performance
- **Auto-Reload Overhead**: ~1-2ns per query (atomic generation check)
  - Thread-local Arc pointer caching eliminates repeated atomic loads
  - Zero locks on query path - pure thread-local access after generation check
  - Automatic cache invalidation when database reloads
  - Benchmark: `benches/reload_overhead_bench.rs` measures overhead vs baseline

### Changed
- **Worker API**: `Worker::add_database()` now accepts `Arc<Database>` instead of `Database`
  - Eliminates unsafe clone operations that caused segfaults in parallel mode
  - Multiple workers can efficiently share the same database via Arc
  - Breaking change: wrap databases in Arc when passing to Worker
  - Migration: `worker.add_database("id", Arc::new(db))` instead of `worker.add_database("id", db)`

### Fixed
- **Critical: Segmentation Fault in Parallel Mode**
  - Fixed unsafe `Clone` implementation on `Database` that used `std::ptr::read()` to bitwise copy `Mmap`
  - `Mmap` is `Send but not Sync` and does not support bitwise copying
  - Removed unsafe `Clone` implementations from both `Database` and `Paraglob`
  - Changed parallel processing to use `Arc<Database>` for safe sharing across threads
  - All 243 library tests + 34 CLI tests now pass in parallel mode

### Dependencies
- Added `arc-swap = "1.7"` for lock-free Arc pointer swapping

### Removed
- Deprecated `Database::open()` method (use `Database::from(path).open()` instead)
- Unsafe `Clone` implementations on `Database` and `Paraglob` structs

## [1.2.2] - 2025-11-07

### Fixed
- **FreeBSD Support**: Fixed build failure on FreeBSD due to Linux-specific `MADV_HUGEPAGE` constant
  - Added FreeBSD-specific memory optimization using `MADV_NOSYNC`
  - All 224 tests passing on FreeBSD 14.1

### Added
- FreeBSD CI testing to catch platform-specific issues

## [1.2.0] - 2025-10-28

### Added
- **String Interning for Database Size Reduction**
  - Automatic deduplication of repeated string values in database data sections
  - Significantly reduces database size for datasets with redundant metadata
  - Zero query-time overhead - interning happens at build time
  - Transparent to API users - no code changes required

### Fixed
- **Critical: Database Construction Bugs** (discovered via fuzzing)
  - Fixed UTF-8 boundary bug in case-insensitive glob pattern matching that could create malformed databases
  - Added overflow/underflow validation in IP tree builder to prevent invalid pointer arithmetic
  - Database builder now validates all record values before writing to prevent creating unreadable databases
  - Enhanced input validation during database construction
  - Improved error messages for invalid data pointer calculations

### Changed
- Database loader now provides detailed error messages on invalid pointer arithmetic instead of panicking
- Improved error messages for invalid input during database building
- Better detection and reporting of malformed patterns and IP addresses

## [1.1.0] - 2025-10-25

### Added
- **`matchy extract` Command** for high-performance pattern extraction from logs
  - Extract domains, IPv4/IPv6 addresses, and email addresses from unstructured text
  - Multiple output formats: JSON (NDJSON), CSV, plain text
  - Configurable extraction types with `--types` flag (ipv4, ipv6, domain, email, all)
  - Deduplication mode with `--unique` flag
  - Statistics reporting with `--stats` flag
  - 200-500 MB/s typical throughput
  - Example: `matchy extract access.log --types domain,ipv4 --unique > patterns.txt`

- **Parallel Multi-File Processing** for `matchy match`
  - `-j/--threads` flag for parallel processing (default: auto-detect cores)
  - 2-8x faster throughput on multi-core systems
  - Per-worker LRU caches for optimal performance
  - `--batch-bytes` tuning option for large files
  - Example: `matchy match threats.mxy *.log -j auto --stats`

- **Follow Mode** for `matchy match`
  - `-f/--follow` flag for log tailing (like `tail -f`)
  - Monitors files for changes using file system notifications
  - Processes new lines immediately as they are written
  - Supports parallel processing with multiple files
  - Graceful shutdown on Ctrl+C

- **Live Progress Reporting**
  - `-p/--progress` flag shows live 3-line progress indicator
  - Displays lines processed, matches, hit rate, throughput, elapsed time
  - Candidate breakdown (IPv4, IPv6, domains, emails)
  - Query rate statistics
  - Updates in-place on TTY, periodic snapshots on non-TTY

- **Public Suffix List (PSL) Integration**
  - Embedded PSL data (15,997 entries) for TLD validation
  - Aho-Corasick automaton for fast TLD matching in domain extraction
  - Automatic validation of domain TLDs during extraction
  - Updated to 2025-10-13 PSL snapshot

- **Query Result Caching** for high-throughput workloads
  - Configurable LRU cache with `Database::from().cache_capacity(size)` builder API
  - Disable caching with `Database::from().no_cache()` for memory-constrained environments
  - `clear_cache()` method for cache management
  - Benchmarks show 2-10x speedup at 80%+ cache hit rates
  - Zero overhead when disabled (compile-time branch elimination)
  - Thread-safe with internal RefCell for zero-cost sharing
  - Example: `benches/cache_bench.rs` demonstrates performance characteristics

- **Pattern Extractor API** for log scanning and data extraction
  - SIMD-accelerated extraction of domains, IPv4/IPv6 addresses, and email addresses from unstructured text
  - Zero-copy line scanning with `memchr` for maximum throughput
  - Unicode/IDN domain support with automatic punycode conversion
  - Configurable extraction via `PatternExtractor::builder()`
  - Word boundary detection for accurate pattern identification
  - Binary log support (extracts ASCII patterns from non-UTF-8 data)
  - 23 comprehensive unit tests covering edge cases
  - IPv6 support added to extraction

### Performance
- **AC Automaton Optimizations**
  - Eliminated allocation in case-insensitive matching path
  - Memory-locked AC automaton with `mlock()` for 2.4% speedup
  - Reduced `core::ptr::read` overhead from 12.67% to 9.24%
  - Improved throughput from ~370 MB/s to ~379 MB/s

- **Case-Insensitive Memory Optimization**
  - Optimized memory usage for case-insensitive AC automaton
  - Improved mmap performance

- **Domain Extraction Optimization**
  - Lookup table-based boundary detection (branch-free, O(1))
  - SIMD-accelerated TLD scanning with embedded automaton
  - Direct AC header loading for faster initialization
  - Buffer reuse in extraction loops

- **Pattern Extraction Performance**
  - IPv6 filtering optimizations
  - Pre-allocated buffers for trusted mode
  - Hot path optimizations in AC matching
  - SIMD enhancements for pattern matching

- **Parallel Processing**
  - Sequential mode: 200-500 MB/s throughput
  - Parallel mode: 400-2000 MB/s depending on core count
  - 2 cores: ~1.8x speedup
  - 4 cores: ~3.2x speedup
  - 8 cores: ~5.5x speedup

- **Caching**: 2-10x query speedup with 80%+ hit rates, zero overhead when disabled
- **Unicode TLDs**: Zero-copy domain validation using embedded Aho-Corasick automaton

### Changed
- **CLI Command Restructuring**
  - Modularized command implementation in `src/bin/commands/`
  - Separate modules for each command: build, query, match, extract, inspect, validate, bench
  - Match processor split into modes: sequential, parallel, batched, follow
  - Comprehensive CLI integration tests

- **Pattern Extractor API**
  - Removed `require_valid_tld` field (TLD validation now automatic via PSL)
  - Upgraded `idna` dependency to 1.0 for Unicode domain handling
  - Removed URL extraction (focus on domains, IPs, emails)

### Fixed
- Various clippy warnings and code quality improvements
- Build warnings from removed dependencies

### Dependencies
- Upgraded `idna` to 1.0 for improved Unicode/IDN support
- Added `memchr = "2.7"` for SIMD-accelerated byte searching
- Added `lru = "0.12"` for LRU cache implementation
- Added `notify = "6.1"` for file system watching (follow mode)
- Added `ctrlc = "3.4"` for Ctrl+C handling
- Added `atty = "0.2"` for TTY detection (progress display)

### Internal
- **AC Automaton Alignment Validation**
  - Added alignment checks for Aho-Corasick automaton
  - Ensures ACNode reads are naturally aligned (8-byte boundaries)
  - Comprehensive testing for alignment correctness

- Removed `literal_mph` module and related minimal perfect hash experiments

## [1.0.1] - 2025-10-14

### Fixed
- **Critical: IP Longest Prefix Match Bug** ([#10](https://github.com/sethhall/matchy/issues/10))
  - Fixed insertion order dependency where more specific IP prefixes inserted before less specific ones could be incorrectly overridden
  - Added prefix length tracking to `NodePointer::Data` for proper route specificity comparison
  - Affects both IPv4 and IPv6 address lookups
  - Example: Inserting 192.0.2.1/32 before 192.0.2.0/24 now correctly returns the /32 match
  - This fix is internal only and does not affect the on-disk MMDB format

### Added
- Comprehensive test suite for IP longest prefix matching scenarios
- IPv6 longest prefix match validation tests

## [1.0.0] - 2025-10-13

### 🎉 Major Release - Production Ready

This is the first stable release of matchy, representing a production-ready unified database for IP addresses, string literals, and glob pattern matching. The 1.0.0 release includes database format changes and comprehensive validation infrastructure.

### 🚨 Breaking Changes
- **Database Format**: Updated binary format with new validation metadata (databases must be rebuilt)
- **Match Mode Storage**: Case sensitivity now stored in database metadata (format incompatibility)

### Added
- **Comprehensive Validation System** (`validation.rs` - 3,200+ lines)
  - Three validation levels: Standard (basic checks), Strict (deep analysis), Audit (security review)
  - MMDB format validation: header integrity, metadata consistency, IP tree structure
  - PARAGLOB section validation: AC automaton integrity, pattern consistency checks
  - Safety-critical checks: UTF-8 validation, pointer cycle detection, depth limits, bounds checking
  - IP tree traversal: full recursive validation detecting cycles and orphaned nodes
  - Data section pointer validation: prevents infinite loops from malicious databases
  - CLI commands: `matchy validate` (with `--level` and `--json` flags), `matchy audit` for security analysis
  - C API: `matchy_validate()` function with validation level constants
  - Example: `examples/audit_database.rs` demonstrating validation API usage

- **Case-Insensitive Matching Support**
  - Build-time flag: `-i/--case-insensitive` for `matchy build` command
  - Match mode (case-sensitive/insensitive) persisted in database metadata
  - Case-insensitive literal hash table with automatic query normalization
  - Automatic deduplication of case variants (smaller databases)
  - Zero query-time overhead (simple lowercase conversion)
  - Backward compatible (defaults to case-sensitive)

### Changed
- **CLI Security**: Generated database files now set to read-only (0444 permissions) to protect memory-mapped integrity
- **Database Loader**: Automatically reads and applies match_mode from metadata (no query-time flags needed)
- **Format Version**: Database format updated to support validation metadata and match mode

### Performance
- Validation overhead: ~18-20ms on 193MB database (minimal impact, <0.01% of query time)
- Case-insensitive matching: Zero query-time overhead (normalization at build and lookup)
- All existing performance characteristics maintained from 0.5.x releases

### Testing
- 21 new unit tests for validation system
- All 163 tests passing (increased from 142 in v0.5.x)
- Case-insensitive matching verified for both globs and literals
- Comprehensive validation test coverage

### Documentation
- Updated README.md with validation and case-insensitive matching sections
- Enhanced DEVELOPMENT.md with validation architecture details
- API documentation improvements throughout

## [0.5.2] - 2025-10-12

### 🚀 Major Performance Improvements
- **State-Specific AC Encoding**: 30-57% faster pattern matching
  - ONE encoding (75-80% of states): Single transition stored inline
  - SPARSE encoding (10-15% of states): 2-8 transitions via edge array
  - DENSE encoding (2-5% of states): 9+ transitions via 256-entry lookup table
  - O(1) lookup for high-degree nodes (1KB per dense state)
  - 13% memory reduction overall due to ONE state optimization

- **O(1) Database Loading**
  - AC literal hash table eliminates HashMap construction on load
  - Lazy offset-based pattern data lookups instead of eager deserialization
  - Load time reduced from O(n) to O(1) where n = pattern count
  - <100μs load time maintained at any scale

- **Zero-Copy Optimizations**
  - Added zerocopy derives (FromBytes, IntoBytes, Immutable, KnownLayout)
  - Safe zero-copy header parsing with zerocopy::Ref
  - Upgraded to zerocopy 0.8 with modern trait derivations

- **Trusted Mode** for maximum performance
  - `Database::open_trusted()` API skips UTF-8 validation
  - 15-20% query speedup for databases from trusted sources
  - `--trusted` flag for matchy CLI bench command
  - Safe by default: `Database::open()` still validates

### Added
- **Comprehensive Benchmark Command** (`matchy bench`)
  - 900+ lines of benchmarking infrastructure
  - Benchmarks build time, load time, query performance
  - Supports ip, literal, pattern, and combined database types
  - Configurable entry counts, load iterations, query counts
  - Hit rate control for realistic query distributions
  - Optional temp file mode or persistent output

- **Fuzzing Infrastructure**
  - Comprehensive `docs/FUZZING_GUIDE.md` (663 lines)
  - 5 fuzz targets: pattern_matching, ip_lookup, glob_patterns, data_values, literal_exact_match
  - `fuzz/README.md` (229 lines) and `FUZZ_TARGETS_SUMMARY.md` (71 lines)
  - `fuzz/fuzz_quickstart.sh` automation script
  - cargo-fuzz configuration in fuzz/ directory

- **New Example Programs**
  - `examples/prefix_convention.rs`: Demonstrates custom matching semantics (131 lines)

- **C FFI Additions**
  - `matchy_open_trusted()` for trusted database loading
  - Updated matchy.h header with new API function

### Fixed
- **Critical: UTF-8 Boundary Panic** (discovered by fuzzing)
  - Star wildcard (*) matching could panic on multi-byte UTF-8 characters
  - Fixed by using character boundary iteration instead of byte positions
  - Added `test_utf8_boundary_in_star_matching` regression test
  - Example: Pattern `*4**4\4**4\*` with text containing 'Ż' would crash

- **Critical: Exponential Backtracking / OOM** (discovered by fuzzing)
  - Patterns with multiple wildcards could cause exponential backtracking
  - Fixed by adding step counter (100,000 steps) to limit backtracking
  - Added `test_backtracking_limit` regression test
  - Example: Pattern `*a*b*c*d*e*f*g*h*i*j*k*l*m*n*o*p*` against mismatched text

- MMDB data section pointer resolution
- Windows compilation issues
- Rustdoc warnings
- docs.rs build configuration

### Changed
- **Breaking**: Removed C++ wrapper API (C API remains)
- **Internal**: Paraglob now stores BufferStorage + metadata instead of cached data
- **Internal**: Replace pattern_data_cache with pattern_data_map offset metadata
- **Build**: Minor regression (+5-10% slower build time) for 30-57% faster queries

### Removed
- Obsolete example programs replaced by CLI bench:
  - `examples/large_scale_ip_benchmark.rs`
  - `examples/test_v3_performance.rs`

### Performance
- **Pattern Matching**: 30-57% faster across all benchmarks
  - p10_t10000/high: +103% throughput
  - p100_t10000/high: +106% throughput  
  - p1000_t10000/high: +133% throughput
  - realistic_workload: +49% throughput
- **Database Loading**: O(1) vs O(n), <100μs at any scale
- **Trusted Mode**: 15-20% additional query speedup
- **Memory**: 13% reduction due to ONE state encoding

### Dependencies
- Added `zerocopy = "0.8"` for safe zero-copy parsing

### Testing
- All 79 tests passing
- 5 comprehensive fuzz targets active
- Both critical bugs discovered and fixed within minutes of fuzzing

### Documentation
- Added 64-byte cache-line alignment documentation
- Added cross-platform endianness support documentation
- Updated WARP.md with performance characteristics
- Added trusted vs safe mode trade-off notes
- Comprehensive fuzzing guide and best practices
- Updated README.md with performance claims (7M+ IP, 1M+ pattern queries/sec)
- Better examples with clearer comments

## [0.5.1] - 2025-10-11

### Added
- **cargo-c Configuration** for C/C++ library installation
  - Complete cargo-c metadata in Cargo.toml
  - Headers install to `/usr/local/include/matchy/`
  - Proper pkg-config support with correct include paths
  - `strip_include_path_components` for correct `#include <matchy/matchy.h>`
  - Documentation: `docs/C_INSTALLATION.md` (273 lines)
  - Documentation: `docs/CARGO_C_SETUP.md` with implementation details

### Changed
- Added `capi` feature required by cargo-c
- Updated installation instructions for system-wide library installation

### Documentation
- Updated README.md with installation instructions
- Complete C installation guide with usage examples

### Installation
Users can now install matchy as a system library:
```bash
cargo install cargo-c
sudo cargo cinstall --release --prefix=/usr/local
```

## [0.5.0] - 2025-01-15

### 🚀 Major Performance Improvements
- **Hybrid Lookup Architecture**: Three-tier lookup system for optimal performance
  - Hash table for literal strings: O(1) exact match
  - Aho-Corasick automaton for glob patterns only
  - IP binary trie for IP addresses
- **18x Faster Build Times**: 424K patterns now build in ~1 second (was ~18 seconds)
- **15x Smaller Databases**: ~72 MB for mixed datasets (was 1.1 GB)
- **10-100x Faster Literal Queries**: O(1) hash lookup vs O(n) AC scan

### Added
- **Literal Hash Table** (`literal_hash.rs`)
  - FxHash-based hash table with linear probing
  - Memory-mapped format for zero-copy loading
  - Automatic deduplication of identical data
  - Pattern ID to data offset mapping

- **CSV Input Format**
  - Build databases from CSV files with metadata
  - First column must be "entry" or "key"
  - Automatic type inference (numbers, booleans, strings)
  - Support for multiple CSV files

- **MISP Streaming Import**
  - Low-memory streaming processing of MISP files
  - `MispImporter::build_from_files()` for large datasets
  - Automatic file type detection (skips manifest.json, etc.)
  - IP subnet support (ip-src/netmask, ip-dst/netmask)

- **Enhanced CLI Output**
  - Query results always return JSON arrays
  - Exit codes: 0 = found, 1 = not found
  - Quiet mode (`--quiet`) for scripting
  - Verbose statistics during build
  - Better progress indicators

- **New Database API Methods**
  - `add_literal()` - Explicit literal string (no wildcards)
  - `add_glob()` - Explicit glob pattern
  - `add_ip()` - Explicit IP/CIDR entry
  - `has_literal_data()` - Check for literal support
  - `has_glob_data()` - Check for glob support
  - `has_string_data()` - Check for any string support
  - `literal_count()` - Get literal count
  - `glob_count()` - Get glob count
  - `ip_count()` - Get IP count

- **C API Additions**
  - `matchy_has_literal_data()`
  - `matchy_has_glob_data()`
  - `matchy_has_string_data()`

### Changed
- **Breaking**: Query CLI now always returns JSON arrays (was mixed format)
- **Breaking**: `has_pattern_data()` deprecated in favor of `has_literal_data()` / `has_glob_data()`
- **MISP Import**: All indicators now use explicit `add_literal()` / `add_ip()` methods
- **Auto-detection**: IP parsing is more strict, validates CIDR notation
- **Database Format**: Added MMDB_LITERAL section marker
- **Statistics**: Split `pattern_entries` into `literal_entries` + `glob_entries`
- **Build Process**: Builder now takes ownership on build (fixes double-build bug)

### Fixed
- Builder can now be built multiple times without panic
- CSV parsing errors provide better context
- MISP importer properly handles non-event files
- Glob validation prevents invalid patterns from being accepted
- Memory deduplication during streaming import

### Performance
- **Build Time** (424K patterns):
  - Before: ~18 seconds
  - After: ~1 second (18x faster)
- **Database Size** (424K patterns):
  - Before: 1.1 GB
  - After: ~72 MB (15x smaller)
- **Query Time** (literal matches):
  - 10-100x faster via O(1) hash lookup

### Documentation
- Added comprehensive README section on building databases
- All input formats documented (text, CSV, JSON, MISP)
- Query examples with expected output
- Database inspection guide
- Architecture proposal document (docs/ARCHITECTURE_PROPOSAL.md)
- Better inline code documentation

### Dependencies
- Added `rustc-hash` 2.1.1 for fast FxHash implementation
- Added `csv` 1.3.1 for CSV file parsing

## [0.4.0] - 2025-01-10

### 🎉 Major Changes
- **Project Rename**: `paraglob-rs` → `matchy` - now a unified database for IP addresses and patterns
- **MMDB Integration**: Full MaxMind DB (MMDB) format support for IP address lookups
- **Unified Database**: Single database format supporting both IP addresses and glob patterns
- **v3 Format**: Zero-copy AC literal mapping for O(1) database loading

### Added
- **IP Address Support**
  - IP address and CIDR range matching using binary trie
  - IPv4 and IPv6 support
  - Compatible with MaxMind GeoIP databases
  - Automatic IP vs pattern detection in queries

- **MISP Integration**
  - Direct import from MISP JSON threat feeds
  - Preserves all MISP metadata (tags, threat levels, categories)
  - Automatic indicator type detection (IPs, domains, hashes, URLs)
  - Built-in MISP attribute parsers

- **Unified Database API**
  - `Database::open()` - works with any database format
  - `Database::lookup()` - auto-detects query type (IP or pattern)
  - `QueryResult` enum for type-safe result handling
  - `MmdbBuilder` for building combined IP + pattern databases

- **CLI Tool**
  - `matchy query` - Query databases
  - `matchy inspect` - Inspect database metadata
  - `matchy build` - Build databases from JSON
  - Support for MISP JSON import

- **Data Section (v2 Format)**
  - Rich structured data storage with patterns
  - MMDB-compatible encoding (maps, arrays, strings, numbers)
  - Automatic data deduplication
  - Pattern data retrieval API

- **v3 Format Improvements**
  - Pre-serialized AC literal mapping
  - O(1) database loading (was O(n))
  - Maintains <100μs load time at any scale
  - Backward compatible with v2 format

### Fixed
- Alignment bug in v3 AC literal mapping deserialization
- Memory safety in pointer casting for unaligned data
- All clippy warnings resolved
- Documentation examples updated to use `matchy` crate name

### Changed
- **Breaking**: Crate renamed from `paraglob-rs` to `matchy`
- **Breaking**: All imports now use `matchy::` instead of `paraglob_rs::`
- C API version function now uses `CARGO_PKG_VERSION` automatically
- Project description updated to reflect database capabilities
- GitHub repository renamed to `matchy`

### Performance
- 1.4M queries/sec with 10K patterns (Apple M4)
- 1M queries/sec with 50K patterns (Apple M4)
- 1.5M IP lookups/sec (binary tree)
- <150μs database load time via mmap (all formats)
- ~4ms build time for 1K entries

### Testing
- 93 unit tests (all passing)
- 23 integration tests (all passing)
- 18 doc tests (all passing)
- Total: 134 tests, 100% passing

### Migration from paraglob-rs

```rust
// Old (paraglob-rs)
use paraglob_rs::Paraglob;

// New (matchy)
use matchy::Paraglob;
// or use the unified database API:
use matchy::Database;
```

## [0.3.1] - Previous Release

See paraglob-rs crate for version history before the rename.
