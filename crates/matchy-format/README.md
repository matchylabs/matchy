# matchy-format

Unified database format orchestrating IP tries, glob patterns, and literal string matching.

## Overview

This crate provides the binary format for matchy databases (.mxy files), combining three routing layers into a single memory-mapped file:
- **IP trie** (from matchy-ip-trie) - CIDR/IP → data offsets
- **Glob patterns** (from matchy-paraglob) - Pattern matching → data offsets  
- **Literal hash** (from matchy-literal-hash) - Exact strings → data offsets

## Architecture

```
.mxy File Format:
┌─────────────────────────────┐
│ IP Search Tree (binary trie)│  ← matchy-ip-trie
├─────────────────────────────┤
│ Data Section (deduplicated) │  ← matchy-data-format
├─────────────────────────────┤
│ MMDB_PATTERN separator      │
├─────────────────────────────┤
│ Paraglob Section (optional) │  ← matchy-paraglob
│   - AC automaton            │
│   - Pattern entries         │
│   - Glob segments           │
├─────────────────────────────┤
│ Literal Hash (optional)     │  ← matchy-literal-hash
│   - Hash table              │
│   - String pool             │
├─────────────────────────────┤
│ MMDB Metadata               │
└─────────────────────────────┘
```

## Features

- **Unified format**: Single file for all data types
- **Memory-mapped**: Zero-copy loading
- **MMDB compatible**: Backward compatible with MaxMind DB format
- **Builder API**: High-level interface for database construction
- **FormatError**: Proper error type for format operations

## Usage

```rust
use matchy_format::{MmdbBuilder, MatchMode};
use matchy_data_format::DataValue;
use std::collections::HashMap;

let mut builder = MmdbBuilder::new(MatchMode::CaseSensitive);

// Add IP entry
let mut data = HashMap::new();
data.insert("country".to_string(), DataValue::String("US".to_string()));
builder.add_entry("1.2.3.4", data)?;

// Add pattern entry
let mut data = HashMap::new();
data.insert("category".to_string(), DataValue::String("malware".to_string()));
builder.add_entry("*.evil.com", data)?;

// Build database
let db_bytes = builder.build()?;
std::fs::write("database.mxy", db_bytes)?;
```

## Entry Type Detection

The builder automatically detects entry types:
- **IP addresses**: `1.2.3.4`, `192.168.0.0/16`, `2001:db8::/32`
- **Literal strings**: `example.com` (exact match only)
- **Glob patterns**: `*.example.com`, `file?.txt` (wildcard matching)

## Components

- `mmdb_builder.rs` - High-level database builder
- `mmdb/` - MMDB format structures
- `offset_format.rs` - Binary format definitions
- `endian.rs` - Endianness handling
- `mmap.rs` - Memory-mapped file wrapper
- `error.rs` - FormatError type

## Dependencies

- `matchy-ip-trie` - IP address routing
- `matchy-paraglob` - Glob pattern matching
- `matchy-literal-hash` - Exact string matching
- `matchy-data-format` - Data encoding/decoding
- `matchy-glob` - Glob parsing
- `matchy-match-mode` - Shared MatchMode enum
