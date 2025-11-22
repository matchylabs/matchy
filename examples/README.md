# Examples

This directory contains example programs demonstrating matchy usage and capabilities.

## Development Tools

### `update-psl` (moved to `tools/`)
**Development tool only** - Updates the pre-built Public Suffix List (PSL) Aho-Corasick automaton.
- This tool has been moved to `tools/update-psl/` to isolate its heavy dependencies
- See `tools/update-psl/README.md` for usage

**Run:** `cd tools/update-psl && cargo run`

## Building Databases

### `build_ip_database.rs`
Demonstrates building an IP address database with CIDR ranges:
- Adding IPv4 and IPv6 addresses
- CIDR range support (e.g., `192.168.0.0/16`)
- Attaching rich metadata to each entry
- Building and serializing to MMDB format
- Database statistics

**Run:** `cargo run --example build_ip_database`

### `build_combined_database.rs`
The power of the unified MMDB format - IP addresses AND patterns in one database:
- Combining IP lookups with pattern matching
- Single database for both types of queries
- Shared data section with automatic deduplication
- Real-world threat intelligence use case
- Demonstrates both search trees and Aho-Corasick automaton

**Run:** `cargo run --example build_combined_database`

### `build_misp_database.rs`
Builds a threat intelligence database from MISP JSON files:
- Loads MISP JSON threat intelligence feeds
- Extracts indicators (IPs, domains, hashes, etc.)
- Preserves all metadata (tags, threat levels, events)
- Demonstrates real-world threat intelligence workflow
- Supports multiple input files

**Run:** `cargo run --example build_misp_database -- misp-example.json`

### `custom_metadata.rs`
Shows how to set custom database metadata:
- Custom database type identifiers
- Multi-language descriptions
- Database versioning and branding
- Corporate deployment use case

**Run:** `cargo run --example custom_metadata`

### `incremental_builder.rs`
Demonstrates incremental pattern building with associated data:
- Adding patterns one at a time
- Attaching rich threat intelligence metadata
- Duplicate pattern detection
- Useful for streaming threat feeds
- Pattern data retrieval after building

**Run:** `cargo run --example incremental_builder`

## Querying Databases

### `geoip_query.rs`
Query GeoIP databases (MaxMind format):
- Loading MMDB GeoIP databases
- IP address lookups
- IPv6 support
- Displaying geographic data
- Demo mode with multiple IPs

**Run:** `cargo run --example geoip_query -- GeoLite2-Country.mmdb 8.8.8.8`

### `combined_query.rs`
Querying unified databases with both IP and pattern data:
- Automatic query type detection (IP vs pattern)
- Handling mixed-mode databases
- Displaying results for both query types
- Useful for threat intelligence lookups

**Run:** `cargo run --example combined_query -- combined_database.mmdb`

### `lookup_extracted_demo.rs`
Demonstrates the efficient extract-and-lookup pattern:
- Using `Extractor` to find IPs, domains, and hashes in log lines
- Using `lookup_extracted()` for clean, performant lookups
- Avoiding verbose match statements on `ExtractedItem` variants
- Perfect template for Vector integration and log scanning
- Shows threat detection workflow

**Run:** `cargo run --release --example lookup_extracted_demo`

## Pattern Matching

### `glob_demo.rs`
Educational demo showing glob pattern matching features:
- Basic wildcards (`*`, `?`)
- Character classes (`[...]`, `[!...]`)
- Case sensitivity modes
- Escape sequences
- UTF-8 support
- Performance characteristics

**Run:** `cargo run --example glob_demo`

## C API Examples

### `enhanced_api_test.c`
Demonstrates the enhanced C API for structured data access:
- Building databases from C
- Querying IP addresses
- Navigating nested data structures with `matchy_aget_value`
- Type-safe data access (strings, doubles, etc.)
- Error handling and cleanup
- Compatible with MaxMind GeoIP database format

**Build and run:**
```bash
make -C examples
./examples/enhanced_api_test
```

## Performance & Testing

### `production_test.rs`
Real-world production usage example demonstrating:
- Building pattern matchers
- Matching performance with realistic workloads
- Serialization to disk
- Zero-copy memory-mapped loading
- Multi-process memory sharing benefits
- Batch processing patterns

**Run:** `cargo run --release --example production_test`

### `matchy bench` (Built-in Benchmarking Tool)
Comprehensive benchmarking tool for all database types:
- **IP databases**: Measure build, load, and query performance for IP lookups
- **Pattern databases**: Test glob pattern matching at scale
- **Combined databases**: Benchmark mixed IP + pattern databases
- Configurable entry counts and query iterations
- Multiple load iterations for averaging
- Memory-mapped (mmap) load time measurement
- Queries per second (QPS) metrics
- Optional database file retention for inspection

**Examples:**
```bash
# Quick pattern test (1K patterns)
cargo build --release && ./target/release/matchy bench pattern -n 1000

# Large IP test (1M IPs)
./target/release/matchy bench ip -n 1000000

# Combined database (50K IPs + 50K patterns)
./target/release/matchy bench combined -n 100000

# Custom query count and keep the database
./target/release/matchy bench pattern -n 10000 --query-count 50000 --keep -o test.mmdb

# See all options
./target/release/matchy bench --help
```

## Quick Start

```bash
# Building databases
cargo run --example build_ip_database
cargo run --example build_combined_database
cargo run --example build_misp_database -- misp-example.json

# Querying
cargo run --example geoip_query -- GeoLite2-Country.mmdb 8.8.8.8
cargo run --example combined_query -- combined_database.mmdb

# Pattern matching demo
cargo run --example glob_demo

# C API example
make -C examples
./examples/enhanced_api_test

# Performance validation
cargo run --release --example production_test

# Benchmarking (built-in tool)
cargo build --release
./target/release/matchy bench pattern -n 10000
./target/release/matchy bench ip -n 100000
./target/release/matchy bench combined -n 50000

# Run integration tests
cargo test --test integration_tests
```

## Example Workflow

1. **Build a combined threat database:**
   ```bash
   cargo run --example build_combined_database
   ```

2. **Query it for threats:**
   ```bash
   cargo run --example combined_query -- combined_database.mmdb evil.com
   cargo run --example combined_query -- combined_database.mmdb 192.168.1.100
   ```

3. **Import MISP threat intelligence:**
   ```bash
   cargo run --example build_misp_database -- threat-feed.json
   ```

4. **Benchmark at scale:**
   ```bash
   cargo build --release
   ./target/release/matchy bench pattern -n 50000
   ./target/release/matchy bench ip -n 1000000
   ./target/release/matchy bench combined -n 100000
   ```
