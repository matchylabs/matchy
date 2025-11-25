# matchy-literal-hash

O(1) exact string matching using hash tables with parallel construction.

## Overview

A memory-mapped hash table optimized for exact string lookups. Unlike Aho-Corasick (designed for pattern matching), this provides O(1) lookups for literal strings using XXH64 with sharded parallel construction.

## Features

- **O(1) lookups**: Hash-based exact string matching
- **Parallel construction**: Sharded building for large datasets
- **Memory-mapped**: Zero-copy loading from disk
- **Case modes**: Case-sensitive and case-insensitive matching
- **Efficient format**: Optimized binary layout with alignment

## Usage

```rust
use matchy_literal_hash::{LiteralHashBuilder, MatchMode};

// Build a hash table
let mut builder = LiteralHashBuilder::new(MatchMode::CaseInsensitive);
builder.add_pattern("example.com", 0);
builder.add_pattern("google.com", 1);

let pattern_data = vec![(0, 100), (1, 200)]; // (pattern_id, data_offset)
let bytes = builder.build(&pattern_data)?;

// Load and query
let hash = LiteralHash::from_buffer(&bytes, MatchMode::CaseInsensitive)?;
assert_eq!(hash.lookup("example.com"), Some(0));
assert_eq!(hash.lookup("EXAMPLE.COM"), Some(0)); // Case-insensitive
```

## Architecture

- **Sharded hash table**: Distributes entries across multiple shards for parallel construction
- **XXH64 hashing**: Fast, stable hash function
- **Binary format**: Memory-mappable with magic bytes "LHSH"

## Binary Format

```
[Header]
  magic: "LHSH"
  version: 1
  entry_count, table_size, offsets...

[Shard Offset Table]
  Offsets to each shard in the table

[Hash Table]
  Sharded entries: [hash, string_offset, pattern_id]

[String Pool]
  Concatenated null-terminated strings

[Pattern Mappings]
  (pattern_id, data_offset) pairs
```

## Dependencies

- `matchy-match-mode` - Shared MatchMode enum
- `rustc-hash` - Fast FxHashMap
- `xxhash-rust` - XXH64 implementation
- `rayon` - Parallel shard construction
