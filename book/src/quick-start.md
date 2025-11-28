# Quick Start

Get up and running with Matchy in minutes.

## Installation

### From Source

```bash
git clone https://github.com/matchylabs/matchy
cd matchy
cargo build --release
```

### As a Rust Dependency

Add to your `Cargo.toml`:

```toml
[dependencies]
matchy = "0.5"
```

## Your First Database (Rust)

Here's a complete example that builds and queries a threat intelligence database:

```rust
use matchy::{Database, DatabaseBuilder, MatchMode, DataValue, QueryResult};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create a builder
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    // 2. Add IP address with threat data
    let mut ip_data = HashMap::new();
    ip_data.insert("threat_level".to_string(), DataValue::String("high".to_string()));
    ip_data.insert("score".to_string(), DataValue::Uint32(95));
    builder.add_entry("1.2.3.4", ip_data)?;

    // 3. Add CIDR range
    let mut cidr_data = HashMap::new();
    cidr_data.insert("type".to_string(), DataValue::String("internal".to_string()));
    builder.add_entry("10.0.0.0/8", cidr_data)?;

    // 4. Add glob pattern
    let mut pattern_data = HashMap::new();
    pattern_data.insert("category".to_string(), DataValue::String("malware".to_string()));
    builder.add_entry("*.evil.com", pattern_data)?;

    // 5. Build and save
    let database_bytes = builder.build()?;
    std::fs::write("threats.mxy", &database_bytes)?;
    println!("✅ Database built: {} bytes", database_bytes.len());

    // 6. Open database (memory-mapped)
    let db = Database::open("threats.mxy")?;
    println!("✅ Database loaded in <1ms");

    // 7. Query IP address
    match db.lookup("1.2.3.4")? {
        Some(QueryResult::Ip { data, prefix_len }) => {
            println!("🔍 IP match: {:?} (/{prefix_len})", data);
        }
        _ => println!("No match"),
    }

    // 8. Query pattern
    match db.lookup("malware.evil.com")? {
        Some(QueryResult::Pattern { pattern_ids, data }) => {
            println!("🔍 Pattern match: {} patterns", pattern_ids.len());
            for (i, d) in data.iter().enumerate() {
                if let Some(threat_data) = d {
                    println!("  Pattern {}: {:?}", pattern_ids[i], threat_data);
                }
            }
        }
        _ => println!("No match"),
    }

    Ok(())
}
```

## Your First Database (C)

Complete C example:

```c
#include "matchy.h"
#include <stdio.h>

int main() {
    // 1. Build database
    matchy_builder_t *builder = matchy_builder_new();
    if (!builder) {
        fprintf(stderr, "Failed to create builder\n");
        return 1;
    }

    // 2. Add entries with JSON data
    matchy_builder_add(builder, "1.2.3.4", 
        "{\"threat_level\": \"high\", \"score\": 95}");
    matchy_builder_add(builder, "10.0.0.0/8", 
        "{\"type\": \"internal\"}");
    matchy_builder_add(builder, "*.evil.com", 
        "{\"category\": \"malware\"}");

    // 3. Save to file
    int err = matchy_builder_save(builder, "threats.mxy");
    if (err != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to save database\n");
        matchy_builder_free(builder);
        return 1;
    }
    printf("✅ Database built\n");
    matchy_builder_free(builder);

    // 4. Open database
    matchy_t *db = matchy_open("threats.mxy");
    if (!db) {
        fprintf(stderr, "Failed to open database\n");
        return 1;
    }
    printf("✅ Database loaded\n");

    // 5. Query IP address
    matchy_result_t result = matchy_query(db, "1.2.3.4");
    if (result.found) {
        char *json = matchy_result_to_json(&result);
        printf("🔍 IP match: %s\n", json);
        matchy_free_string(json);
        matchy_free_result(&result);
    }

    // 6. Query pattern
    result = matchy_query(db, "malware.evil.com");
    if (result.found) {
        char *json = matchy_result_to_json(&result);
        printf("🔍 Pattern match: %s\n", json);
        matchy_free_string(json);
        matchy_free_result(&result);
    }

    // 7. Cleanup
    matchy_close(db);
    printf("✅ Done\n");

    return 0;
}
```

Compile and run:

```bash
gcc -o example example.c -I./include -L./target/release -lmatchy
LD_LIBRARY_PATH=./target/release ./example
```

## What Just Happened?

1. **Built a database** - Added IPs, CIDR ranges, and patterns with structured data
2. **Saved to disk** - Wrote optimized binary format (`.mxy` file)
3. **Loaded instantly** - Memory-mapped the file (<1ms load time)
4. **Queried efficiently** - Looked up IPs and patterns in microseconds

## Key Concepts

### Automatic Type Detection

You don't need to specify whether an entry is an IP, CIDR, or pattern. Matchy detects automatically:

```rust
builder.add_entry("1.2.3.4", data)?;        // Detected as IP
builder.add_entry("10.0.0.0/8", data)?;     // Detected as CIDR
builder.add_entry("*.evil.com", data)?;     // Detected as glob pattern
builder.add_entry("evil.com", data)?;       // Detected as exact string
```

### Database Immutability

Databases are **read-only** once built. To update:

1. Create new builder
2. Add all entries (old + new + modified)
3. Build new database
4. Atomically replace old file

This ensures readers always see consistent state.

### Memory Mapping

Databases use `mmap()` for:
- **Instant loading** - No deserialization overhead
- **Memory efficiency** - OS shares pages across processes
- **Large databases** - Work with databases larger than RAM

## Next Steps

- [Installation Guide](getting-started/installation.md) - Detailed setup instructions
- [Rust API Guide](reference/rust-api.md) - Complete Rust API documentation
- [C API Guide](reference/c-api.md) - Complete C API documentation
- [Architecture](architecture/overview.md) - How Matchy works internally
