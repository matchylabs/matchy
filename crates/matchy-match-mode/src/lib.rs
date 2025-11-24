//! Match mode configuration for text matching operations.
//!
//! This crate provides the `MatchMode` enum which controls case-sensitivity
//! in pattern matching operations across the matchy ecosystem.

/// Match mode for text matching operations.
///
/// Controls whether text comparisons are case-sensitive or case-insensitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    /// Case-sensitive matching - "abc" matches "abc" but not "ABC"
    CaseSensitive,
    /// Case-insensitive matching - "abc" matches "ABC", "Abc", etc.
    CaseInsensitive,
}
