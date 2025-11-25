# matchy-glob

Fast glob pattern matching with wildcards and character classes.

## Overview

Efficient glob pattern matching supporting `*`, `?`, `[...]`, and `[!...]` syntax with both case-sensitive and case-insensitive modes.

## Features

- **Wildcards**: `*` (zero or more chars), `?` (single char)
- **Character classes**: `[abc]` (match a, b, or c), `[!abc]` (match anything but a, b, or c)
- **Ranges**: `[a-z]`, `[0-9]`
- **Case modes**: Case-sensitive and case-insensitive matching
- **Zero allocations**: Stack-based matching with no heap usage
- **Fast**: Optimized for common patterns

## Usage

```rust
use matchy_glob::{GlobPattern, MatchMode};

// Create a pattern
let pattern = GlobPattern::new("*.example.com", MatchMode::CaseInsensitive)?;

// Match against text
assert!(pattern.is_match("foo.example.com"));
assert!(pattern.is_match("bar.example.com"));
assert!(!pattern.is_match("example.com")); // * requires at least one char

// Character classes
let pattern = GlobPattern::new("file[0-9].txt", MatchMode::CaseSensitive)?;
assert!(pattern.is_match("file5.txt"));
assert!(!pattern.is_match("fileA.txt"));
```

## Pattern Syntax

| Pattern | Matches | Example |
|---------|---------|---------|
| `*` | Zero or more characters | `*.com` matches `example.com` |
| `?` | Exactly one character | `file?.txt` matches `file1.txt` |
| `[abc]` | One character from set | `[aeiou]` matches vowels |
| `[!abc]` | One character NOT in set | `[!0-9]` matches non-digits |
| `[a-z]` | One character in range | `[A-Z]` matches uppercase |

## Performance

- Pattern compilation: ~100ns
- Matching: ~50-500ns depending on pattern complexity
- No allocations during matching

## Dependencies

- `matchy-match-mode` - Shared MatchMode enum
