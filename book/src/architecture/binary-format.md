# Binary Format

Detailed binary format specification for Matchy databases.

## File Structure

A `.mxy` file consists of two main sections: the required MMDB section and an optional PARAGLOB extension:

```mermaid
block-beta
  columns 1
  block:mmdb["MMDB Section (Required)"]:1
    meta["MMDB Metadata Header"]
    tree["IP Binary Search Tree"]
    data["Shared Data Section"]
  end
  space:1
  block:para["PARAGLOB Section (Optional)"]:1
    magic["Magic: 'PARAGLOB'"]
    header["Format Header"]
    ac["Aho-Corasick Automaton"]
    strings["String Hash Index"]
  end
  
  style mmdb fill:#e1f5ff,stroke:#0288d1,stroke-width:2px
  style para fill:#fff3e0,stroke:#ef6c00,stroke-width:2px,stroke-dasharray: 5 5
  style data fill:#c8e6c9,stroke:#388e3c,stroke-width:2px
```

The PARAGLOB section is only present when the database includes string literals or glob patterns. IP-only databases contain just the MMDB section.

## MMDB Section

Standard MaxMind DB format:
- See [MaxMind DB Spec](https://maxmind.github.io/MaxMind-DB/)

## PARAGLOB Section

### Header

```rust
#[repr(C)]
struct ParaglobHeader {
    magic: [u8; 8],      // "PARAGLOB"
    version: u32,        // Format version
    num_nodes: u32,      // AC automaton nodes
    nodes_offset: u32,   // Offset to nodes
    num_literals: u32,   // Literal count
    literals_offset: u32,// Offset to literals
}
```

### AC Node

```rust
#[repr(C)]
struct AcNode {
    failure_offset: u32, // Failure link
    edges_offset: u32,   // Edge array
    num_edges: u16,      // Edge count
    output_offset: u32,  // Match data
}
```

### Literal Entry

```rust
#[repr(C)]
struct LiteralEntry {
    hash: u64,           // String hash
    string_offset: u32,  // String data
    data_offset: u32,    // Associated data
}
```

## Endianness

All multi-byte integers use **native byte order** (little-endian on x86/ARM via `#[repr(C)]`).

The format stores an endianness marker (0x01 for little-endian) for future compatibility,
but currently only little-endian is supported since it represents >99.9% of deployments.

## Alignment

All structures are naturally aligned:
- `u8`: 1-byte alignment
- `u16`: 2-byte alignment
- `u32`: 4-byte alignment
- `u64`: 8-byte alignment

## See Also

- [MMDB Integration](../mmdb-integration-design.md) - How the format maintains compatibility
- [System Architecture](overview.md) - Overall system design
- [Performance Results](performance-results.md) - Format performance characteristics
