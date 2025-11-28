# Changelog

All notable changes to matchy are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For detailed version history, see the [full CHANGELOG.md](https://github.com/matchylabs/matchy/blob/main/CHANGELOG.md) in the repository.

## [1.2.1] - 2025-10-28

### Fixed
- **Critical: Worker False Positive Bug**
  - Fixed bug where Worker was treating `QueryResult::NotFound` as a valid match
  - Affects batch processing and `matchy match` command accuracy
  - Now correctly distinguishes between matches and non-matches

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

- **Parallel Multi-File Processing** for `matchy match`
  - `-j/--threads` flag for parallel processing (default: auto-detect cores)
  - 2-8x faster throughput on multi-core systems
  - Per-worker LRU caches for optimal performance
  - `--batch-bytes` tuning option for large files

- **Follow Mode** for `matchy match`
  - `-f/--follow` flag for log tailing (like `tail -f`)
  - Monitors files for changes using file system notifications
  - Processes new lines immediately as they are written
  - Supports parallel processing with multiple files

- **Live Progress Reporting**
  - `-p/--progress` flag shows live 3-line progress indicator
  - Displays lines processed, matches, hit rate, throughput, elapsed time
  - Candidate breakdown (IPv4, IPv6, domains, emails)
  - Query rate statistics

- **Query Result Caching** for high-throughput workloads
  - Configurable LRU cache with `Database::from().cache_capacity(size)` builder API
  - Disable caching with `Database::from().no_cache()` for memory-constrained environments
  - `clear_cache()` method for cache management
  - Benchmarks show 2-10x speedup at 80%+ cache hit rates

- **Pattern Extractor API** for log scanning and data extraction
  - SIMD-accelerated extraction of domains, IPv4/IPv6 addresses, and email addresses
  - Zero-copy line scanning with `memchr` for maximum throughput
  - Unicode/IDN domain support with automatic punycode conversion
  - Binary log support (extracts ASCII patterns from non-UTF-8 data)

### Performance
- **AC Automaton Optimizations**: 2.4% speedup from memory-locked automaton
- **Parallel Processing**: 2-8x speedup on multi-core systems
- **Caching**: 2-10x query speedup with 80%+ hit rates

## [1.0.1] - 2025-10-14

### Fixed
- **Critical: IP Longest Prefix Match Bug** ([#10](https://github.com/matchylabs/matchy/issues/10))
  - Fixed insertion order dependency affecting IP address lookups
  - More specific prefixes (e.g., /32) now correctly take precedence over less specific ones (e.g., /24)
  - Affects both IPv4 and IPv6 lookups
  - Internal fix only - no database format changes

### Added
- Comprehensive test suite for longest prefix matching
- IPv6 longest prefix match tests

## [1.0.0] - 2025-10-13

### 🎉 First Stable Release

Matchy 1.0.0 is production-ready! This major release includes database format updates and comprehensive validation infrastructure.

### 🚨 Breaking Changes
- **Database Format**: Updated binary format (databases from v0.5.x must be rebuilt)
- **Match Mode Storage**: Case sensitivity now stored in database metadata

### Highlights

**Validation System**
- Three validation levels: Standard, Strict, and Audit
- Complete database integrity checking before loading
- CLI commands: `matchy validate` and `matchy audit`
- C API: `matchy_validate()` function
- Prevents crashes from corrupted or malicious databases

**Case-Insensitive Matching**
- Build-time `-i/--case-insensitive` flag
- Match mode persisted in database metadata
- Zero query-time overhead
- Automatic deduplication of case variants

**Performance**
- Validation: ~18-20ms on 193MB database (minimal impact)
- All 0.5.x performance characteristics maintained:
  - 7M+ IP queries/second
  - 1M+ pattern queries/second
  - <100μs database loading
  - 30-57% faster than 0.4.x pattern matching

**Testing**
- 163 tests passing (all unit, integration, and doc tests)
- 5 active fuzz targets
- Comprehensive validation coverage

## [0.5.2] - 2025-10-12

### Major Performance Improvements
- **30-57% faster pattern matching** via state-specific AC encoding
- **O(1) database loading** with lazy offset-based lookups
- **Trusted mode** for 15-20% additional speedup (skips validation)

### Critical Bug Fixes
- Fixed UTF-8 boundary panic in glob matching (found by fuzzing)
- Fixed exponential backtracking / OOM vulnerability (found by fuzzing)

### Added
- Comprehensive `matchy bench` command (900+ lines)
- Fuzzing infrastructure with 5 fuzz targets
- Zero-copy optimizations with zerocopy 0.8
- `Database::open_trusted()` API

## [0.5.1] - 2025-10-11

### Added
- cargo-c configuration for C/C++ library installation
- System-wide installation support: `cargo cinstall`
- Headers install to `/usr/local/include/matchy/`

## [0.5.0] - 2025-01-15

### Major Performance Improvements
- **18x faster build times** (424K patterns in ~1 second)
- **15x smaller databases** (~72 MB vs 1.1 GB)
- **10-100x faster literal queries** via O(1) hash lookup

### Added
- Hybrid lookup architecture (hash table + Aho-Corasick + IP trie)
- Literal hash table for exact string matching
- CSV input format support
- MISP streaming import
- Enhanced CLI with JSON output and exit codes

## [0.4.0] - 2025-01-10

### Major Changes
- **Project renamed** from `paraglob-rs` to `matchy`
- Full MMDB integration for IP address lookups
- Unified database format (IP addresses + patterns)
- v3 format with zero-copy AC literal mapping

### Added
- IP address and CIDR range matching (IPv4 and IPv6)
- MISP threat feed integration
- CLI tool: `matchy query`, `matchy inspect`, `matchy build`
- Rich structured data storage (MMDB-compatible encoding)

### Performance
- 1.4M queries/sec with 10K patterns
- 1.5M IP lookups/sec
- <150μs database load time

---

## Release Process

Releases follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.x): Incompatible API or format changes
- **MINOR** (x.1): New backward-compatible functionality
- **PATCH** (x.x.1): Backward-compatible bug fixes

## See Also

- [Full CHANGELOG.md](https://github.com/matchylabs/matchy/blob/main/CHANGELOG.md)
- [Contributing](contributing.md)
- [Development Guide](development.md)
