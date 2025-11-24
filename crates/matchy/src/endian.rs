//! Endianness handling for zero-copy cross-platform support
//!
//! This module provides endianness-aware wrappers for reading multi-byte values
//! from memory-mapped databases. The database is stored in little-endian format
//! (native to x86/ARM) and byte-swapped on-demand for big-endian systems.
//!
//! # Design Philosophy
//!
//! **Zero-copy on little-endian (99% of deployments)**:
//! - All reads compile to direct memory access with no overhead
//! - Inlining ensures branch elimination at compile time
//!
//! **Correct on big-endian**:
//! - Byte swapping happens transparently via accessor methods
//! - Still zero-copy (no buffer rewriting), just CPU byte swap on read
//!
//! # Usage Pattern
//!
//! ```rust
//! use matchy::endian::{read_u32_le, read_u16_le, read_u32_le_field};
//!
//! // Create a sample buffer
//! let buffer = [0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0];
//! let offset = 0;
//!
//! // Reading from buffer
//! let value = unsafe { read_u32_le(&buffer, offset) };
//! assert_eq!(value, 0x12345678);
//!
//! // Reading struct fields
//! struct ACNode { node_id: u32 }
//! let node = ACNode { node_id: 0x12345678u32.to_le() };
//! let node_id = read_u32_le_field(node.node_id);
//! assert_eq!(node_id, 0x12345678);
//! ```
//!
//! # Performance
//!
//! On little-endian (x86, ARM):
//! - Zero overhead - compiles to direct load
//! - `read_u32_le(buf, 0)` → `mov eax, [buf]`
//!
//! On big-endian (POWER, SPARC):
//! - Single CPU instruction for byte swap
//! - `read_u32_le(buf, 0)` → `lwbrx r3, 0, buf` (load byte-reversed)

use std::mem;

/// Endianness marker stored in database header
///
/// This allows runtime detection of endianness mismatches.
/// - 0x01 = little-endian (x86, ARM, RISC-V)
/// - 0x02 = big-endian (POWER, SPARC, older systems)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndiannessMarker {
    /// Little-endian byte order (x86, ARM, RISC-V)
    LittleEndian = 0x01,
    /// Big-endian byte order (POWER, SPARC, older systems)
    BigEndian = 0x02,
}

impl EndiannessMarker {
    /// Get the native endianness of this system
    #[inline]
    pub const fn native() -> Self {
        #[cfg(target_endian = "little")]
        {
            EndiannessMarker::LittleEndian
        }
        #[cfg(target_endian = "big")]
        {
            EndiannessMarker::BigEndian
        }
    }

    /// Check if we need byte swapping when reading this database
    #[inline]
    pub const fn needs_swap(self) -> bool {
        !matches!(
            (self, Self::native()),
            (
                EndiannessMarker::LittleEndian,
                EndiannessMarker::LittleEndian
            ) | (EndiannessMarker::BigEndian, EndiannessMarker::BigEndian)
        )
    }

    /// Convert from raw byte value
    #[inline]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(EndiannessMarker::LittleEndian),
            0x02 => Some(EndiannessMarker::BigEndian),
            _ => None,
        }
    }
}

/// Read a u32 in little-endian format from buffer
///
/// On little-endian systems: compiles to direct load (zero overhead)
/// On big-endian systems: uses CPU byte-swap instruction
///
/// # Safety
///
/// Caller must ensure `offset + 4 <= buffer.len()`
#[inline(always)]
pub unsafe fn read_u32_le(buffer: &[u8], offset: usize) -> u32 {
    debug_assert!(offset + 4 <= buffer.len());
    let ptr = buffer.as_ptr().add(offset) as *const u32;
    u32::from_le(ptr.read_unaligned())
}

/// Read a u16 in little-endian format from buffer
///
/// # Safety
///
/// Caller must ensure `offset + 2 <= buffer.len()`
#[inline(always)]
pub unsafe fn read_u16_le(buffer: &[u8], offset: usize) -> u16 {
    debug_assert!(offset + 2 <= buffer.len());
    let ptr = buffer.as_ptr().add(offset) as *const u16;
    u16::from_le(ptr.read_unaligned())
}

/// Read a u32 field from a struct in little-endian format
///
/// Use this when you have a reference to a struct and want to read
/// one of its u32 fields with proper endianness handling.
///
/// # Example
///
/// ```ignore
/// let node: &ACNode = get_node(buffer, offset);
/// let node_id = read_u32_le_field(node.node_id);
/// ```
#[inline(always)]
pub fn read_u32_le_field(value: u32) -> u32 {
    #[cfg(target_endian = "little")]
    {
        value
    }
    #[cfg(target_endian = "big")]
    {
        value.swap_bytes()
    }
}

/// Read a u16 field from a struct in little-endian format
#[inline(always)]
pub fn read_u16_le_field(value: u16) -> u16 {
    #[cfg(target_endian = "little")]
    {
        value
    }
    #[cfg(target_endian = "big")]
    {
        value.swap_bytes()
    }
}

/// Write a u32 in little-endian format to buffer
///
/// # Safety
///
/// Caller must ensure `offset + 4 <= buffer.len()`
#[inline(always)]
pub unsafe fn write_u32_le(buffer: &mut [u8], offset: usize, value: u32) {
    debug_assert!(offset + 4 <= buffer.len());
    let ptr = buffer.as_mut_ptr().add(offset) as *mut u32;
    ptr.write_unaligned(value.to_le());
}

/// Write a u16 in little-endian format to buffer
///
/// # Safety
///
/// Caller must ensure `offset + 2 <= buffer.len()`
#[inline(always)]
pub unsafe fn write_u16_le(buffer: &mut [u8], offset: usize, value: u16) {
    debug_assert!(offset + 2 <= buffer.len());
    let ptr = buffer.as_mut_ptr().add(offset) as *mut u16;
    ptr.write_unaligned(value.to_le());
}

/// Convert u32 value to little-endian for storage
#[inline(always)]
pub const fn to_le_u32(value: u32) -> u32 {
    value.to_le()
}

/// Convert u16 value to little-endian for storage
#[inline(always)]
pub const fn to_le_u16(value: u16) -> u16 {
    value.to_le()
}

/// Helper to read struct with endianness handling
///
/// This provides a zero-copy view of a struct from the buffer,
/// but all multi-byte fields must be accessed through endian-aware
/// accessor methods.
///
/// # Safety
///
/// Caller must ensure:
/// - `offset + size_of::<T>() <= buffer.len()`
/// - Buffer is properly aligned for T (or use read_unaligned)
/// - Struct fields will be read with proper endian accessors
#[inline]
pub unsafe fn read_struct_ref<T>(buffer: &[u8], offset: usize) -> &T {
    debug_assert!(offset + mem::size_of::<T>() <= buffer.len());
    let ptr = buffer.as_ptr().add(offset) as *const T;
    &*ptr
}

/// Helper to read slice of structs with endianness handling
///
/// # Safety
///
/// Same requirements as read_struct_ref, but for a slice
#[inline]
pub unsafe fn read_struct_slice<T>(buffer: &[u8], offset: usize, count: usize) -> &[T] {
    debug_assert!(offset + mem::size_of::<T>() * count <= buffer.len());
    let ptr = buffer.as_ptr().add(offset) as *const T;
    std::slice::from_raw_parts(ptr, count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endianness_marker() {
        let native = EndiannessMarker::native();

        #[cfg(target_endian = "little")]
        {
            assert_eq!(native, EndiannessMarker::LittleEndian);
            assert!(!native.needs_swap());
            assert!(EndiannessMarker::BigEndian.needs_swap());
        }

        #[cfg(target_endian = "big")]
        {
            assert_eq!(native, EndiannessMarker::BigEndian);
            assert!(!native.needs_swap());
            assert!(EndiannessMarker::LittleEndian.needs_swap());
        }
    }

    #[test]
    fn test_read_write_u32() {
        let mut buffer = [0u8; 8];

        unsafe {
            write_u32_le(&mut buffer, 0, 0x12345678);
            write_u32_le(&mut buffer, 4, 0xDEADBEEF);
        }

        // Check little-endian byte order in buffer
        assert_eq!(buffer[0], 0x78);
        assert_eq!(buffer[1], 0x56);
        assert_eq!(buffer[2], 0x34);
        assert_eq!(buffer[3], 0x12);

        assert_eq!(buffer[4], 0xEF);
        assert_eq!(buffer[5], 0xBE);
        assert_eq!(buffer[6], 0xAD);
        assert_eq!(buffer[7], 0xDE);

        // Read back
        unsafe {
            assert_eq!(read_u32_le(&buffer, 0), 0x12345678);
            assert_eq!(read_u32_le(&buffer, 4), 0xDEADBEEF);
        }
    }

    #[test]
    fn test_read_write_u16() {
        let mut buffer = [0u8; 4];

        unsafe {
            write_u16_le(&mut buffer, 0, 0x1234);
            write_u16_le(&mut buffer, 2, 0xABCD);
        }

        // Check little-endian byte order
        assert_eq!(buffer[0], 0x34);
        assert_eq!(buffer[1], 0x12);
        assert_eq!(buffer[2], 0xCD);
        assert_eq!(buffer[3], 0xAB);

        // Read back
        unsafe {
            assert_eq!(read_u16_le(&buffer, 0), 0x1234);
            assert_eq!(read_u16_le(&buffer, 2), 0xABCD);
        }
    }

    #[test]
    fn test_field_accessors() {
        // These should work regardless of native endianness
        let value_u32: u32 = 0x12345678;
        let value_u16: u16 = 0xABCD;

        let read_u32 = read_u32_le_field(to_le_u32(value_u32));
        let read_u16 = read_u16_le_field(to_le_u16(value_u16));

        assert_eq!(read_u32, value_u32);
        assert_eq!(read_u16, value_u16);
    }

    #[test]
    fn test_endianness_conversion() {
        // Test that to_le and from_le are inverses
        let original: u32 = 0xDEADBEEF;
        let stored = to_le_u32(original);

        #[cfg(target_endian = "little")]
        assert_eq!(stored, original);

        #[cfg(target_endian = "big")]
        assert_eq!(stored, original.swap_bytes());

        let retrieved = read_u32_le_field(stored);
        assert_eq!(retrieved, original);
    }
}
