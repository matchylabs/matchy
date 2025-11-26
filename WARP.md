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

# Run examples (includes perf test)
cargo run --release --example production_test
cargo run --release --example glob_demo
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
    -I./include \
    -L./target/release \
    -lmatchy \
    -lpthread -ldl -lm

# Run with memory checking
valgrind --leak-check=full --show-leak-kinds=all ./myapp
```

## Repository Structure

### Project Layout

```
matchy/
├── src/                    # Rust source code
│   ├── lib.rs              # Public API, version constants, module declarations
│   ├── ac_offset.rs        # Offset-based Aho-Corasick automaton implementation
│   ├── paraglob_offset.rs  # High-level Paraglob API with glob matching
│   ├── glob.rs             # Glob pattern matching logic (wildcards, character classes)
│   ├── offset_format.rs    # Binary format structures (#[repr(C)])
│   ├── serialization.rs    # Save/load/mmap functions
│   ├── mmap.rs             # Memory-mapped file wrapper
│   ├── error.rs            # ParaglobError type and conversions
│   ├── binary/             # Binary format implementation
│   │   ├── mod.rs          # Module exports
│   │   ├── format.rs       # #[repr(C)] structures for binary format
│   │   └── validation.rs   # Format validation and offset checking
│   └── c_api/              # C FFI layer
│       └── mod.rs          # extern "C" functions, opaque handles, error codes
├── tests/
│   └── integration_tests.rs  # End-to-end integration tests
├── benches/
│   ├── cache_bench.rs           # Caching performance (integration)
│   ├── reload_overhead_bench.rs # Hot reload overhead (integration)
│   ├── mmdb_build_bench.rs      # MMDB builder perf (integration)
│   ├── batch_bench.rs           # Batch processing perf (integration)
│   └── query_profile.rs         # Memory allocation profiling (dhat)
├── crates/
│   ├── matchy-paraglob/
│   │   └── benches/
│   │       └── paraglob_bench.rs   # Core pattern matching perf
│   └── matchy-extractor/
│       └── benches/
│           └── extraction_bench.rs # Text extraction perf
├── examples/
│   ├── glob_demo.rs          # Basic glob pattern demonstrations
│   └── production_test.rs    # Production workload simulation
├── include/
│   └── matchy.h         # Auto-generated C header (cbindgen)
├── Cargo.toml              # Package metadata, dependencies, build profiles
├── build.rs                # Build script (runs cbindgen)
├── cbindgen.toml           # cbindgen configuration
├── README.md               # Project overview, usage examples
├── DEVELOPMENT.md          # Architecture, benchmarks, design decisions
└── WARP.md                 # This file
```

### Module Responsibilities

| Module | Purpose |
|--------|----------|
| **lib.rs** | Public API surface, version info, module organization |
| **ac_offset.rs** | Aho-Corasick automaton with offset-based pointers for mmap |
| **paraglob_offset.rs** | Main Paraglob struct, pattern matching orchestration |
| **glob.rs** | Glob syntax parsing and matching (*, ?, [], [!]) |
| **offset_format.rs** | Binary format definitions with stable layout |
| **serialization.rs** | High-level save/load/mmap API |
| **processing.rs** | Batch processing infrastructure (LineFileReader, Worker, etc.) |
| **file_reader.rs** | Streaming file I/O with automatic gzip decompression |
| **binary/** | Low-level binary format reading/writing/validation |
| **mmap.rs** | Safe wrapper around memory-mapped files |
| **c_api/** | C FFI with opaque handles, error codes |
| **error.rs** | Error types (Rust-style) and C conversion |


## Best Practices

### Code Style

- Use `cargo fmt` before committing - formatting is enforced
- Run `cargo clippy` and address warnings - keep the codebase clean
- Add doc comments (`///`) for all public items
- Write tests for new functionality - maintain 79/79 passing
- Use descriptive variable names - clarity over brevity in this codebase

### Safety Guidelines

**Unsafe code is only permitted at FFI boundaries.** Core algorithms must be safe Rust.

When working with unsafe:
1. Document why unsafe is necessary
2. Keep unsafe blocks as small as possible
3. Validate all assumptions with comments
4. Add safety documentation (`# Safety` section)

### Binary Format Changes

All binary format structures use `#[repr(C)]` for stable cross-platform compatibility:

```rust
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OffsetAcHeader {
    pub magic: [u8; 8],     // Magic bytes: "PARAGLOB"
    pub version: u32,       // Format version
    pub num_nodes: u32,     // Node count
    pub nodes_offset: u32,  // Offset to node table
    // ...
}
```

**Critical**: Any changes to these structures break binary compatibility. If you must change:
1. Update the version number
2. Test thoroughly with existing databases
3. Verify byte-by-byte .mxy file compatibility
4. Update DEVELOPMENT.md with format changes

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
