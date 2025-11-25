# Binary Format Specification

Matchy databases use the MaxMind DB (MMDB) format with custom extensions for string and pattern matching.

## Overview

The format has two main sections:

1. **MMDB Section**: Standard MaxMind DB format for IP address lookups
2. **PARAGLOB Section**: Custom extension for string/pattern matching

Both sections coexist in a single `.mxy` file.

## File Structure

```
┌─────────────────────────────────────────────────────────┐
│  MMDB Metadata (start of file)               │  Standard MMDB header
├─────────────────────────────────────────────────────────┤
│  IP Address Trie                              │  Binary trie for IP lookups
├─────────────────────────────────────────────────────────┤
│  Data Section                                  │  MMDB data values
├─────────────────────────────────────────────────────────┤
│  Search Tree Metadata                         │  Marks end of MMDB section
├─────────────────────────────────────────────────────────┤
│  PARAGLOB Section Marker                      │  Magic bytes: "PARAGLOB"
├─────────────────────────────────────────────────────────┤
│  Pattern Matching Automaton                   │  Aho-Corasick state machine
├─────────────────────────────────────────────────────────┤
│  Exact String Hash Table                      │  O(1) string lookups
└─────────────────────────────────────────────────────────┘
```

## MMDB Section

### Header

Standard MMDB metadata map at the start of the file:

```json
{
  "binary_format_major_version": 2,
  "binary_format_minor_version": 0,
  "build_epoch": 1234567890,
  "database_type": "Matchy",
  "description": {
    "en": "Matchy unified database"
  },
  "ip_version": 6,
  "node_count": 12345,
  "record_size": 28
}
```

### Search Tree

Binary trie for IP address lookups:

- **Node size**: 7 bytes (28-bit pointers × 2)
- **Record size**: 28 bits per record
- **Addressing**: Supports up to 256M nodes

Each node contains two 28-bit pointers (left/right):

```
Node (7 bytes):
├─ Left pointer  (28 bits) → next node or data
└─ Right pointer (28 bits) → next node or data
```

### Data Section

MMDB-format data types:

| Type | Code | Size | Notes |
|------|------|------|-------|
| Pointer | 1 | Variable | Offset into data section |
| String | 2 | Variable | UTF-8 text |
| Double | 3 | 8 bytes | IEEE 754 |
| Bytes | 4 | Variable | Binary data |
| Uint16 | 5 | 2 bytes | Unsigned integer |
| Uint32 | 6 | 4 bytes | Unsigned integer |
| Map | 7 | Variable | Key-value pairs |
| Int32 | 8 | 4 bytes | Signed integer |
| Uint64 | 9 | 8 bytes | Unsigned integer |
| Boolean | 14 | 0 bytes | Value in type byte |
| Float | 15 | 4 bytes | IEEE 754 |
| Array | 11 | Variable | Ordered list |

See [MaxMind DB Format](https://maxmind.github.io/MaxMind-DB/) for encoding details.

## PARAGLOB Section

Located after the MMDB search tree metadata.

### Section Header

```rust
struct ParaglobHeader {
    magic: [u8; 8],      // "PARAGLOB"
    version: u32,        // Format version (currently 1)
    num_nodes: u32,      // Automaton node count
    nodes_offset: u32,   // Offset to node array
    num_edges: u32,      // Total edge count
    edges_offset: u32,   // Offset to edge array
    strings_size: u32,   // Size of string table
    strings_offset: u32, // Offset to string table
    hash_size: u32,      // Hash table size
    hash_offset: u32,    // Offset to hash table
}
```

**Size**: 44 bytes, aligned to 8-byte boundary

### Automaton Nodes

Array of Aho-Corasick automaton nodes:

```rust
struct AcNode {
    failure_offset: u32,    // Offset to failure node
    edges_offset: u32,      // Offset to first edge
    num_edges: u16,         // Number of outgoing edges
    is_terminal: u8,        // 1 if pattern ends here
    pattern_id: u32,        // Pattern ID if terminal
    data_offset: u32,       // Offset to associated data
}
```

**Size**: 19 bytes per node, aligned

### Edges

Array of state transitions:

```rust
struct AcEdge {
    byte: u8,          // Input byte
    target_offset: u32, // Target node offset
}
```

**Size**: 5 bytes per edge

Edges are sorted by byte value for binary search.

### String Table

Concatenated null-terminated strings:

```
offset 0: "example.com\0"
offset 12: "*.google.com\0"
offset 25: "test\0"
...
```

Referenced by offset from other structures.

### Hash Table

For exact string matching:

```rust
struct HashBucket {
    string_offset: u32,  // Offset into string table
    data_offset: u32,    // Offset to data
    next_offset: u32,    // Next bucket (collision chain)
}
```

**Size**: 12 bytes per bucket

Hash function: FNV-1a

## Data Alignment

All structures are aligned:

- **Header**: 8-byte alignment
- **Nodes**: 8-byte alignment
- **Edges**: 4-byte alignment
- **Hash buckets**: 4-byte alignment

Padding bytes are zeros.

## Offset Encoding

All offsets are relative to the start of the PARAGLOB section:

```
File offset = PARAGLOB_SECTION_START + relative_offset
```

Special values:
- `0x00000000` = NULL pointer
- `0xFFFFFFFF` = Invalid/end marker

## Version History

### Version 1 (Current)

- Initial format
- Support for patterns, exact strings, and IP addresses
- Aho-Corasick automaton for pattern matching
- Hash table for exact matches
- Embedded MMDB data format

## Format Validation

Matchy validates these invariants on load:

1. **Magic bytes match**: MMDB at start, "PARAGLOB" at extension
2. **Version supported**: Only version 1 currently
3. **Offsets in bounds**: All offsets point within file
4. **Alignment correct**: Structures properly aligned
5. **No cycles**: Failure links form a DAG
6. **Strings null-terminated**: All strings end with `\0`
7. **Edge ordering**: Edges sorted by byte value

Validation errors result in `CorruptData` errors.

## Memory Mapping

The format is designed for memory mapping:

- **No pointer fixups**: All offsets are file-relative
- **No relocations**: Position-independent
- **Aligned access**: Natural alignment for all types
- **Bounds checkable**: All sizes/offsets in header

Example:

```rust
let file = File::open("database.mxy")?;
let mmap = unsafe { Mmap::map(&file)? };

// Direct access to structures
let header = read_paraglob_header(&mmap)?;
let nodes = get_node_array(&mmap, header.nodes_offset)?;
```

## Cross-Platform Compatibility

Format is platform-independent:

- **Endianness**: Native byte order (little-endian on x86/ARM). Marker stored for future big-endian support if needed.
- **Alignment**: Conservative alignment for all platforms
- **Sizes**: Fixed-size types (`u32`, not `size_t`)
- **ABI**: `#[repr(C)]` structures

A database built on Linux/x86-64 works on macOS/ARM64 (both little-endian).

## Future Extensions

Reserved fields for future versions:

- Pattern compilation flags (case sensitivity, etc.)
- Compressed string tables
- Alternative hash functions
- Additional data formats

Version changes will be backward-compatible when possible.

## See Also

- [MMDB Format Spec](https://maxmind.github.io/MaxMind-DB/)
- [Aho-Corasick Algorithm](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm)
- [FNV Hash](http://www.isthe.com/chongo/tech/comp/fnv/)
- [Data Types Reference](data-types-ref.md)
