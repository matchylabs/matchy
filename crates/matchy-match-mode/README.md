# matchy-match-mode

Shared match mode enum for the matchy workspace.

## Overview

This tiny crate (10 lines, zero dependencies) provides the `MatchMode` enum used across all matchy crates to specify case-sensitive or case-insensitive matching.

```rust
pub enum MatchMode {
    CaseSensitive,
    CaseInsensitive,
}
```

## Why a separate crate?

By extracting `MatchMode` into its own crate, we eliminate circular dependencies between other workspace crates that all need to reference this shared type.

## Usage

```rust
use matchy_match_mode::MatchMode;

let mode = MatchMode::CaseInsensitive;
```

## Features

- Zero dependencies
- `Copy + Clone + Debug + PartialEq + Eq`
- Used by: matchy-glob, matchy-ac, matchy-paraglob, matchy-literal-hash, matchy-format
