# Binary Format Specification

Detailed binary format specification for Matchy databases.

Matchy databases use the MaxMind DB (MMDB) format with optional extensions for string and pattern matching.

## Overview

The format has three main components:

1. **MMDB Section**: Standard MaxMind DB format for IP address lookups
2. **PARAGLOB Section**: Optional extension for glob pattern matching
3. **String Literals Hash Section**: Optional extension for exact string matching

All components coexist in a single `.mxy` file.

## File Structure

**Note**: The MMDB format is unusual - it has no header or magic bytes at the start. The file begins directly with the IP search tree, and all metadata is stored at the end of the file.

```
┌─────────────────────────────────────────────────────────┐
│  IP Search Tree (Binary Trie)                │  Starts at byte 0
├─────────────────────────────────────────────────────────┤
│  16-byte separator                            │
├─────────────────────────────────────────────────────────┤
│  Data Section (Shared)                        │  MMDB data values
├─────────────────────────────────────────────────────────┤
│  MMDB_PATTERN separator (optional)            │  "MMDB_PATTERN\x00\x00\x00\x00"
├─────────────────────────────────────────────────────────┤
│  PARAGLOB SECTION (optional)                  │  Glob pattern matching
├─────────────────────────────────────────────────────────┤
│  MMDB_LITERAL separator (optional)            │  "MMDB_LITERAL\x00\x00\x00\x00"
├─────────────────────────────────────────────────────────┤
│  STRING LITERALS HASH SECTION (optional)      │  O(1) exact string lookups
├─────────────────────────────────────────────────────────┤
│  Metadata Marker                              │  "\xAB\xCD\xEFMaxMind.com"
├─────────────────────────────────────────────────────────┤
│  MMDB Metadata (within last 128KB)            │  node_count, record_size, etc.
└─────────────────────────────────────────────────────────┘
```

### Section Descriptions

**IP Search Tree**: Binary trie for IP address lookups. This is the first data in the file (offset 0). The tree structure depends on metadata fields that are only available after parsing the metadata at the end of the file.

**Data Section**: Shared MMDB-encoded data values referenced by all query types (IP, pattern, and literal lookups).

**PARAGLOB Section**: Optional section for glob pattern matching. Only present if the database contains patterns with wildcards (e.g., `*.example.com`).

**String Literals Hash Section**: Optional hash table for O(1) exact string matching. Only present if the database contains literal strings (non-wildcard patterns).

**MMDB Metadata**: Contains essential database information:
- `node_count`: Number of nodes in the IP search tree
- `record_size`: Size of tree records (24, 28, or 32 bits)
- `ip_version`: IPv4 (4) or IPv6 (6)
- `pattern_section_offset`: Offset to PARAGLOB section (0 if absent)
- `literal_section_offset`: Offset to literal hash section (0 if absent)
- Build timestamp, database type, description, etc.

The metadata marker (`\xAB\xCD\xEFMaxMind.com`) is located within the last 128KB of the file. Parsers search backwards from the end to find it.

## MMDB Section

The file follows the standard MaxMind DB format:
- See [MaxMind DB Spec](https://maxmind.github.io/MaxMind-DB/)

Key characteristics:
- No header at start of file
- File begins with IP search tree data at offset 0
- Metadata stored at end of file for fast tail access
- Memory-mappable with zero-copy access

### Metadata

Standard MMDB metadata map at the end of the file (after metadata marker):

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

## PARAGLOB Section Format

When glob patterns are present, the PARAGLOB section contains:

```rust
#[repr(C)]
struct ParaglobHeader {
    magic: [u8; 8],           // "PARAGLOB"
    version: u32,             // Format version (currently 5)
    match_mode: u32,          // 0=CaseSensitive, 1=CaseInsensitive
    ac_node_count: u32,       // Number of AC automaton nodes
    ac_nodes_offset: u32,     // Offset to node array
    // ... additional fields for pattern data
}
```

Followed by:
- Aho-Corasick automaton nodes and edges
- Pattern metadata entries
- Glob segment data
- Pattern-to-data mappings

See `matchy-format/src/offset_format.rs` for the complete `ParaglobHeader` structure (112 bytes in v5).

## String Literals Hash Section Format

When literal strings are present, a hash table section provides O(1) lookups:

```rust
// Hash table with open addressing
struct LiteralHashSection {
    // Serialized hash table from matchy-literal-hash
    // Format: capacity + array of (hash, pattern_id, data_offset)
}
```

See `matchy-literal-hash` crate for implementation details.

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

### Version 5 (Current)

- Serialized glob segments for zero-copy loading
- Optimized memory layout with ACNodeHot (16 bytes)
- Support for patterns, exact strings, and IP addresses
- Aho-Corasick automaton for pattern matching
- Separate hash table for exact literal matches
- Embedded MMDB data format

### Previous Versions

- **v4**: ACNodeHot (20-byte) for 50% memory reduction
- **v3**: AC literal mapping for O(1) zero-copy loading
- **v2**: Data section support for pattern-associated data
- **v1**: Original format, patterns only

## Format Validation

Matchy validates these invariants on load:

1. **Magic bytes match**: "\xAB\xCD\xEFMaxMind.com" at end, "PARAGLOB" if pattern section present
2. **Version supported**: PARAGLOB version 5 currently
3. **Offsets in bounds**: All offsets point within file
4. **Alignment correct**: Structures properly aligned
5. **Section offsets**: Metadata contains correct `pattern_section_offset` and `literal_section_offset`
6. **File size**: Must be at least large enough for tree + metadata

Validation errors result in format errors. See `matchy validate` command for detailed validation.

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
