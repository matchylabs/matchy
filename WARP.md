# WARP.md

Guidance for working with the matchy codebase.

## Project Overview

**matchy** is a production-ready unified database for IP addresses, string literals, and glob pattern matching. Built in Rust, it provides:
- Fast IP address lookups using binary trie
- Exact string matching with hash tables
- Multi-pattern glob matching using Aho-Corasick algorithm
- Zero-copy memory-mapped file support
- Extended MMDB format with backwards compatibility

**Status**: ✅ Production Ready
- 243/243 tests passing
- Excellent performance across all query types
- Zero-copy glob pattern matching (v5 format)
- Stable binary format for cross-platform use
- Stable C FFI for cross-language use

### Design Principles

1. **Unified database**: Single file format for IP addresses, strings, and patterns
2. **Zero-copy architecture**: Offset-based data structures enable direct memory mapping
3. **Memory safety**: Core algorithms in safe Rust; unsafe code only at FFI boundaries
4. **Performance**: Optimized data structures for each query type
5. **FFI stability**: C API uses opaque handles and integer error codes
6. **Binary stability**: `#[repr(C)]` structures for cross-platform compatibility

## Documentation

Key documents:
- **README.md** - Project overview, performance metrics, usage examples
- **DEVELOPMENT.md** - Architecture details, benchmarks, implementation notes
- **examples/README.md** - How to run example programs
- **Cargo docs** - `cargo doc --no-deps --open` for API documentation

## Development Workflow

### Building

```bash
# Development build
cargo build

# Optimized build (with LTO, single codegen unit)
cargo build --release

# Check without building
cargo check
```

The release build automatically generates `include/matchy.h` via cbindgen.

### Testing

```bash
# Run all tests (243 tests)
cargo test

# Run with output visible
cargo test -- --nocapture

# Run specific test
cargo test test_ac_basic

# Run integration tests
cargo test --test integration_tests

# Run with backtrace on failure
RUST_BACKTRACE=1 cargo test
```

### Code Quality

```bash
# Format code
cargo fmt

# Check formatting without modifying
cargo fmt -- --check

# Run clippy lints
cargo clippy

# Clippy with warnings as errors
cargo clippy -- -D warnings

# Check for common issues
cargo clippy -- -W clippy::all -W clippy::pedantic
```

### Performance

```bash
# Run all workspace benchmarks
cargo bench

# Run subcrate benchmarks
cargo bench -p matchy-paraglob
cargo bench -p matchy-extractor

# Run matchy (integration) benchmarks
cargo bench -p matchy

# Memory profiling (allocation analysis)
cargo bench -p matchy --bench query_profile --features dhat-heap

# Run examples
cargo run --release --example extractor_demo
cargo run --release --example build_combined_database
```

### Documentation

#### Rust API Documentation

```bash
# Generate and open docs
cargo doc --no-deps --open

# Generate docs for all dependencies
cargo doc --open
```

#### mdbook User Documentation

**Important**: All mdbook commands must be run from the `book/` directory.

```bash
# Build the book
cd book
mdbook build

# Serve with live reload during editing
cd book
mdbook serve
# Then open http://localhost:3000

# Or from project root
(cd book && mdbook build)
```

The book uses preprocessors that require the working directory to be `book/`:
- `mdbook-project-version` - Injects version from Cargo.toml
- `mdbook-cmdrun` - Executes command examples (via `run-cmdrun.sh` wrapper)
- `mdbook-mermaid` - Renders Mermaid diagrams

See `book/README.md` for details on command output management and regeneration.

### C Integration Testing

```bash
# Compile and link C program against library
gcc -o myapp app.c \
    -I./crates/matchy/include \
    -L./target/release \
    -lmatchy \
    -lpthread -ldl -lm

# Run with memory checking
valgrind --leak-check=full --show-leak-kinds=all ./myapp
```

## Repository Structure

### Project Layout

Matchy is a Cargo workspace with multiple crates for modular architecture:

```
matchy/
├── Cargo.toml                    # Workspace root
├── crates/
│   ├── matchy/                   # Main integration crate (binary + library)
│   │   ├── src/
│   │   │   ├── lib.rs            # Public API surface, re-exports
│   │   │   ├── database.rs       # Unified Database API
│   │   │   ├── processing.rs     # Batch processing (Worker, LineFileReader)
│   │   │   ├── validation.rs     # Database validation
│   │   │   ├── serialization.rs  # Save/load/mmap functions
│   │   │   ├── file_reader.rs    # Streaming I/O with gzip support
│   │   │   ├── misp_importer.rs  # MISP JSON threat intelligence importer
│   │   │   ├── simd_utils.rs     # SIMD-accelerated operations
│   │   │   ├── error.rs          # Error types and conversions
│   │   │   ├── bin/              # CLI binary implementation
│   │   │   │   ├── matchy.rs     # Main CLI entry point
│   │   │   │   ├── cli_utils.rs  # CLI utilities
│   │   │   │   ├── commands/     # CLI subcommands
│   │   │   │   └── match_processor/ # Match processing logic
│   │   │   ├── c_api/            # C FFI layer
│   │   │   │   └── mod.rs        # extern "C" functions, opaque handles
│   │   │   └── data/             # Test data files
│   │   ├── tests/                # Integration tests
│   │   │   ├── integration_tests.rs
│   │   │   ├── cli_tests.rs
│   │   │   ├── test_ip_*.rs
│   │   │   ├── test_literal_hash.rs
│   │   │   ├── thread_safety_tests.rs
│   │   │   └── auto_reload_test.rs
│   │   ├── benches/              # Performance benchmarks
│   │   │   ├── cache_bench.rs
│   │   │   ├── batch_bench.rs
│   │   │   ├── mmdb_build_bench.rs
│   │   │   ├── reload_overhead_bench.rs
│   │   │   └── query_profile.rs
│   │   ├── examples/             # Example programs
│   │   │   ├── build_ip_database.rs
│   │   │   ├── build_combined_database.rs
│   │   │   ├── build_misp_database.rs
│   │   │   ├── combined_query.rs
│   │   │   ├── extractor_demo.rs
│   │   │   ├── hash_demo.rs
│   │   │   ├── parallel_processing.rs
│   │   │   ├── cache_demo.rs
│   │   │   ├── geoip_query.rs
│   │   │   └── *.c (C examples)
│   │   ├── include/              # Generated C headers
│   │   │   └── matchy.h          # Auto-generated by cbindgen
│   │   ├── build.rs              # Build script (runs cbindgen)
│   │   └── cbindgen.toml         # cbindgen configuration
│   │
│   ├── matchy-format/            # Binary format and MMDB implementation
│   │   ├── src/
│   │   │   ├── lib.rs            # Format types and builder
│   │   │   ├── mmdb_builder.rs   # DatabaseBuilder for creating databases
│   │   │   ├── offset_format.rs  # Binary format structures (#[repr(C)])
│   │   │   ├── validation.rs     # Format validation
│   │   │   ├── mmap.rs           # Memory-mapped file wrapper
│   │   │   ├── error.rs          # Format-specific errors
│   │   │   └── mmdb/             # MMDB format implementation
│   │   │       ├── mod.rs
│   │   │       ├── format.rs     # MMDB binary structures
│   │   │       ├── types.rs      # MMDB data types
│   │   │       └── tree.rs       # MMDB tree structures
│   │   └── tests/                # Format tests
│   │
│   ├── matchy-ip-trie/           # IP address search tree
│   │   └── src/
│   │       ├── lib.rs            # Binary trie for IP lookups
│   │       └── validation.rs     # Trie validation
│   │
│   ├── matchy-literal-hash/      # Exact string matching
│   │   └── src/
│   │       ├── lib.rs            # Hash table for O(1) exact matches
│   │       └── validation.rs     # Hash table validation
│   │
│   ├── matchy-paraglob/          # Glob pattern matching
│   │   ├── src/
│   │   │   ├── lib.rs            # Paraglob API
│   │   │   ├── paraglob_offset.rs # Pattern matching orchestration
│   │   │   ├── glob.rs           # Glob syntax (*, ?, [], [!])
│   │   │   ├── offset_format.rs  # Pattern binary format
│   │   │   ├── literal_hash.rs   # Literal pattern optimization
│   │   │   ├── error.rs          # Pattern matching errors
│   │   │   ├── validation.rs     # Pattern validation
│   │   │   └── simd_utils.rs     # SIMD optimizations
│   │   └── benches/
│   │       └── paraglob_bench.rs # Pattern matching performance
│   │
│   ├── matchy-ac/                # Aho-Corasick automaton
│   │   └── src/
│   │       ├── lib.rs            # Offset-based AC automaton
│   │       └── validation.rs     # AC structure validation
│   │
│   ├── matchy-extractor/         # Text extraction (domains, IPs, emails)
│   │   ├── src/
│   │   │   └── lib.rs            # Fast pattern extraction from text
│   │   ├── benches/
│   │   │   └── extraction_bench.rs
│   │   └── tools/                # Extractor utilities
│   │
│   ├── matchy-data-format/       # Data value types
│   │   └── src/
│   │       ├── lib.rs            # DataValue enum (String, Int, etc.)
│   │       └── validation.rs     # Data validation
│   │
│   └── matchy-match-mode/        # Match mode configuration
│       └── src/
│           └── lib.rs            # CaseSensitive/CaseInsensitive enum
│
├── book/                         # mdbook documentation
│   ├── src/                      # Markdown source files
│   │   ├── introduction.md
│   │   ├── getting-started/      # CLI and API tutorials
│   │   ├── guide/                # Conceptual guides
│   │   ├── commands/             # CLI reference
│   │   ├── reference/            # API reference
│   │   └── appendix/             # Glossary and examples
│   ├── book.toml                 # mdbook configuration
│   ├── command-outputs/          # Saved command outputs
│   └── README.md                 # Book build instructions
│
├── benchmarks/                   # Benchmark data and scripts
├── scripts/                      # Build and test scripts
├── fuzz/                         # Fuzzing tests
├── tools/                        # Development tools
├── README.md                     # Project overview
├── DEVELOPMENT.md                # Architecture details
└── WARP.md                       # This file
```

### Crate Responsibilities

| Crate | Purpose |
|-------|----------|
| **matchy** | Main integration crate: CLI binary, public API, unified Database, processing |
| **matchy-format** | Binary format structures, MMDB builder, mmap handling |
| **matchy-ip-trie** | IP address lookups via binary trie |
| **matchy-literal-hash** | O(1) exact string matching |
| **matchy-paraglob** | Glob pattern matching with Aho-Corasick |
| **matchy-ac** | Offset-based Aho-Corasick automaton |
| **matchy-extractor** | Fast extraction of IPs, domains, emails from text |
| **matchy-data-format** | DataValue type for database entries |
| **matchy-match-mode** | CaseSensitive/CaseInsensitive configuration |

### Main Crate Module Responsibilities

| Module (matchy crate) | Purpose |
|--------|----------|
| **lib.rs** | Public API surface, re-exports from subcrates |
| **database.rs** | Unified Database API for IP and pattern queries |
| **processing.rs** | Batch processing (Worker, LineFileReader, LineBatch) |
| **validation.rs** | Database validation for untrusted files |
| **serialization.rs** | High-level save/load/mmap API |
| **file_reader.rs** | Streaming file I/O with automatic gzip decompression |
| **misp_importer.rs** | MISP JSON threat intelligence importer |
| **simd_utils.rs** | SIMD-accelerated operations (ASCII lowercase, etc.) |
| **error.rs** | Error types (MatchyError, FormatError, ParaglobError) |
| **c_api/** | C FFI with opaque handles, error codes |
| **bin/** | CLI implementation (matchy.rs, commands, match_processor) |


## Best Practices

### Code Style

- Use `cargo fmt` before committing - formatting is enforced
- Run `cargo clippy` and address warnings - keep the codebase clean
- Add doc comments (`///`) for all public items
- Write tests for new functionality - maintain 243/243 passing
- Use descriptive variable names - clarity over brevity in this codebase

### Safety Guidelines

**Unsafe code is only permitted at FFI boundaries.** Core algorithms must be safe Rust.

When working with unsafe:
1. Document why unsafe is necessary
2. Keep unsafe blocks as small as possible
3. Validate all assumptions with comments
4. Add safety documentation (`# Safety` section)

### Binary Format Changes

All binary format structures use `#[repr(C)]` for stable cross-platform compatibility.

Binary format structures are defined in:
- `matchy-format/src/offset_format.rs` - MMDB format structures
- `matchy-format/src/mmdb/format.rs` - MMDB-specific structures
- `matchy-ac/src/lib.rs` - Aho-Corasick node structures
- `matchy-paraglob/src/offset_format.rs` - Pattern matching structures

Example:
```rust
#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ACNodeHot {
    pub state_kind: u8,         // State encoding type
    pub one_char: u8,           // Single transition character
    pub edge_count: u8,         // Number of edges
    pub pattern_count: u8,      // Number of pattern IDs
    pub one_target: u32,        // Single transition target
    pub failure_offset: u32,    // Failure link offset
    pub edges_offset: u32,      // Edges array offset
    pub patterns_offset: u32,   // Pattern IDs offset
}
```

**Critical**: Any changes to these structures break binary compatibility. If you must change:
1. Update the version number in the relevant format module
2. Test thoroughly with existing databases
3. Verify byte-by-byte .mxy file compatibility
4. Update DEVELOPMENT.md with format changes
5. Consider adding migration code if needed

### Testing Strategy

When adding new features:

```bash
# 1. Write unit tests in the same file
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_your_feature() {
        // test code
    }
}

# 2. Run tests frequently
cargo test

# 3. Add integration tests for complex workflows
# tests/integration_tests.rs

# 4. Benchmark if performance-sensitive
# benches/paraglob_bench.rs
```

## Implementation Patterns

### FFI Safety

All `extern "C"` functions must:

1. **Validate all pointers** before dereferencing:
```rust
if db.is_null() || text.is_null() {
    return PARAGLOB_ERROR_INVALID_PARAM;
}
```

2. **Use panic catching** at FFI boundaries:
```rust
let result = std::panic::catch_unwind(|| {
    // ... actual logic ...
});
result.unwrap_or(PARAGLOB_ERROR_UNKNOWN)
```

3. **Convert Rust types safely**:
```rust
let text = unsafe { CStr::from_ptr(text) }
    .to_str()
    .ok()?;
```

4. **Use opaque handles** for ownership transfer:
```rust
// Transfer to C
Box::into_raw(Box::new(db))

// Reclaim from C
unsafe { drop(Box::from_raw(db)); }
```

### Offset-Based Access Pattern

Unlike pointer-based structures, all references use file offsets:

```rust
pub struct AcNode {
    failure_offset: u32,  // Not a pointer!
    edges_offset: u32,
    num_edges: u16,
    // ...
}

impl AcNode {
    fn get_failure_node<'a>(&self, buffer: &'a [u8]) -> Result<&'a AcNode> {
        // Validate offset bounds and alignment first!
        validate_offset::<AcNode>(buffer, self.failure_offset as usize)?;
        
        // Safe after validation
        Ok(unsafe { 
            &*(buffer.as_ptr().add(self.failure_offset as usize) as *const AcNode)
        })
    }
}
```

**Always validate offsets** before dereferencing to prevent undefined behavior.

## Common Patterns

### Validating Offsets

Always validate before dereferencing:

```rust
fn validate_offset<T>(buffer: &[u8], offset: usize) -> Result<()> {
    let size = std::mem::size_of::<T>();
    
    // Bounds check
    if offset + size > buffer.len() {
        return Err(ParaglobError::CorruptData { 
            offset, 
            reason: "Offset out of bounds" 
        });
    }
    
    // Alignment check
    if offset % std::mem::align_of::<T>() != 0 {
        return Err(ParaglobError::CorruptData {
            offset,
            reason: "Misaligned offset"
        });
    }
    
    Ok(())
}
```

### Converting Rust Errors to C

```rust
fn to_c_error(err: ParaglobError) -> paraglob_error_t {
    match err {
        ParaglobError::IoError(e) if e.kind() == ErrorKind::NotFound 
            => PARAGLOB_ERROR_FILE_NOT_FOUND,
        ParaglobError::InvalidFormat { .. } 
            => PARAGLOB_ERROR_INVALID_FORMAT,
        ParaglobError::CorruptData { .. } 
            => PARAGLOB_ERROR_CORRUPT_DATA,
        _ => PARAGLOB_ERROR_UNKNOWN,
    }
}
```

## Debugging Tips

### Enable Debug Output

```bash
# With cargo test
RUST_LOG=debug cargo test -- --nocapture

# With release builds
RUST_LOG=matchy=trace cargo run --release
```

### Inspecting Binary Format

```bash
# Hex dump of matchy database (shows internal PARAGLOB section if present)
hexdump -C patterns.mxy | head -20

# Check magic bytes (MMDB metadata marker)
xxd patterns.mxy | head -1

# Compare two database files
diff <(xxd db1.mxy) <(xxd db2.mxy)
```

### Memory Debugging

```bash
# Address sanitizer (Linux/macOS)
RUSTFLAGS="-Z sanitizer=address" cargo +nightly test

# Leak detection
valgrind --leak-check=full ./test_c_api

# Undefined behavior (Miri)
cargo +nightly miri test
```

## Integration with Parent Project

Matchy is part of the larger `mmdb_with_strings` project:

- **Parent directory**: `/Users/seth/factual/mmdb_with_strings/`
- **libmaxminddb**: `../libmaxminddb/` - MaxMind DB integration
- **Parent WARP.md**: `../WARP.md` - Broader project context

Matchy extends the MMDB format to support string and pattern matching alongside traditional IP address lookups.

## Cargo Profile Settings

The project uses these profiles:

```toml
[profile.release]
opt-level = 3
lto = true              # Link-time optimization
codegen-units = 1       # Better optimization
panic = "abort"         # Don't unwind through FFI
strip = false           # Keep symbols initially

[profile.dev]
opt-level = 0
debug = true

[profile.bench]
inherits = "release"
```

**Note**: `panic = "abort"` is critical - panics must never cross FFI boundaries!

## Processing Module API

The `processing` module provides infrastructure for efficient batch-oriented file analysis. These are general-purpose building blocks that work sequentially or can be used to build parallel pipelines.

### Core Types

```rust
// Minimal match result - no file/line context
pub struct MatchResult {
    pub matched_text: String,     // "192.168.1.1"
    pub match_type: String,        // "IPv4", "IPv6", "Domain", "Email"
    pub result: QueryResult,       // Database result with data
    pub database_id: String,       // Which DB matched: "threats.mxy"
    pub byte_offset: usize,        // Offset in input data (0-indexed)
}

// Match with line context (for line-oriented processing)
pub struct LineMatch {
    pub match_result: MatchResult, // Core match info
    pub source: PathBuf,           // File path, "-" for stdin, or any label
    pub line_number: usize,        // Line number (1-indexed)
}

// Pre-chunked batch of line-oriented data
pub struct LineBatch {
    pub source: PathBuf,              // Source label (file, "-", etc.)
    pub starting_line_number: usize,  // First line number (1-indexed)
    pub data: Arc<Vec<u8>>,           // Raw byte data
    pub line_offsets: Arc<Vec<usize>>, // Pre-computed newline positions
}

// Accumulated processing statistics
pub struct WorkerStats {
    pub lines_processed: usize,
    pub candidates_tested: usize,
    pub matches_found: usize,
    pub lines_with_matches: usize,
    pub total_bytes: usize,
    pub ipv4_count: usize,
    pub ipv6_count: usize,
    pub domain_count: usize,
    pub email_count: usize,
}
```

### LineFileReader - File Chunking

Reads files in line-oriented chunks with automatic gzip decompression.

```rust
pub struct LineFileReader { /* ... */ }

impl LineFileReader {
    // Create new reader
    // Supports .gz files via extension detection
    pub fn new<P: AsRef<Path>>(path: P, chunk_size: usize) -> io::Result<Self>
    
    // Read next batch (returns None at EOF)
    pub fn next_batch(&mut self) -> io::Result<Option<LineBatch>>
    
    // Iterator interface
    pub fn batches(self) -> LineBatchIter
}
```

**Example:**
```rust
use matchy::processing::LineFileReader;

let reader = LineFileReader::new("access.log.gz", 128 * 1024)?;
for batch in reader.batches() {
    let batch = batch?;
    println!("Batch: {} lines", batch.line_offsets.len());
}
```

### Worker - Batch Processing

Processes batches with extraction + database matching. Supports multiple databases.

```rust
pub struct Worker { /* ... */ }

impl Worker {
    // Builder pattern for multi-database support
    pub fn builder() -> WorkerBuilder
    
    // Process raw bytes without line tracking
    pub fn process_bytes(&mut self, data: &[u8]) -> Result<Vec<MatchResult>, String>
    
    // Process LineBatch with automatic line number calculation
    pub fn process_lines(&mut self, batch: &LineBatch) -> Result<Vec<LineMatch>, String>
    
    // Get accumulated statistics
    pub fn stats(&self) -> &WorkerStats
    
    // Reset statistics to zero
    pub fn reset_stats(&mut self)
}

pub struct WorkerBuilder { /* ... */ }

impl WorkerBuilder {
    pub fn extractor(self, extractor: Extractor) -> Self
    pub fn add_database(self, id: impl Into<String>, db: Database) -> Self
    pub fn build(self) -> Worker
}
```

**Example (single database):**
```rust
use matchy::{Database, processing};
use matchy::extractor::Extractor;

let db = Database::from("threats.mxy").open()?;
let extractor = Extractor::new()?;

let mut worker = processing::Worker::builder()
    .extractor(extractor)
    .add_database("threats", db)
    .build();

let reader = processing::LineFileReader::new("access.log", 128 * 1024)?;
for batch in reader.batches() {
    let batch = batch?;
    let matches = worker.process_lines(&batch)?;
    
    for m in matches {
        println!("{}:{} - {} found in {}", 
            m.source.display(), m.line_number,
            m.match_result.matched_text, m.match_result.database_id);
    }
}
```

**Example (multiple databases):**
```rust
let threats_db = Database::from("threats.mxy").open()?;
let allowlist_db = Database::from("allowlist.mxy").open()?;

let mut worker = processing::Worker::builder()
    .extractor(extractor)
    .add_database("threats", threats_db)
    .add_database("allowlist", allowlist_db)
    .build();

// Each match includes database_id to show which DB matched
let matches = worker.process_bytes(b"Check 192.168.1.1")?;
for m in matches {
    println!("{} found in {}", m.matched_text, m.database_id);
}
```

**Example (non-file processing):**
```rust
// For matchy-app or other non-file use cases
let text = "Check this IP: 192.168.1.1";
let matches: Vec<MatchResult> = worker.process_bytes(text.as_bytes())?;

for m in matches {
    println!("{} ({}): {:?}", m.matched_text, m.match_type, m.result);
    // No file/line context - just the match
}
```

### Design Rationale

**Why two match types?**
- `MatchResult`: Core match info, useful everywhere (desktop app, web service, etc.)
- `LineMatch`: Adds file/line context, only for line-oriented processing

**Why multiple databases?**
- Check multiple threat feeds
- Cross-reference allowlists and blocklists  
- Tag matches by source ("found in threat-db-1, not in allowlist-db-2")
- Extract once, query N databases (more efficient than N separate passes)

**Why process_bytes() and process_lines()?**
- `process_bytes()`: General-purpose, no line assumptions (matchy-app, streaming)
- `process_lines()`: Convenience for file processing, computes line numbers automatically

**Why PathBuf for source?**
- Flexible labeling: real file paths, "-" for stdin, "tcp://..." for network streams
- Common convention, works with Display for output
