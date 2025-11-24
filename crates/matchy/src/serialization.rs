//! Serialization and file I/O for Paraglob
//!
//! This module provides simple save/load operations for Paraglob pattern databases.
//! File loading uses memory mapping for instant, zero-copy operation with shared
//! memory across processes.

use crate::error::ParaglobError;
use crate::glob::MatchMode as GlobMatchMode;
use crate::paraglob_offset::Paraglob;
use memmap2::Mmap;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Memory-mapped Paraglob
///
/// Holds both the memory mapping and the Paraglob instance.
/// The mmap ensures data remains valid for the Paraglob's lifetime.
///
/// # Memory Sharing
///
/// When multiple processes load the same file, the OS shares the
/// physical memory pages between them, providing significant memory
/// savings for large pattern databases.
pub struct MmappedParaglob {
    #[allow(dead_code)]
    mmap: Mmap,
    paraglob: Paraglob,
}

impl MmappedParaglob {
    /// Get a reference to the Paraglob
    pub fn paraglob(&self) -> &Paraglob {
        &self.paraglob
    }

    /// Get a mutable reference to the Paraglob
    pub fn paraglob_mut(&mut self) -> &mut Paraglob {
        &mut self.paraglob
    }
}

/// Save a Paraglob to a file
///
/// The file can be instantly loaded later with zero copying.
///
/// # Example
///
/// ```no_run
/// use matchy::paraglob_offset::Paraglob;
/// use matchy::MatchMode;
/// use matchy::serialization::save;
///
/// let patterns = vec!["*.txt", "test_*"];
/// let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();
/// save(&pg, "patterns.mxy").unwrap();
/// ```
///
/// **Note:** This is a low-level API for standalone pattern files. Most users should
/// use the unified `Database` and `DatabaseBuilder` APIs instead, which create `.mxy`
/// files with optional IP and pattern data.
pub fn save<P: AsRef<Path>>(paraglob: &Paraglob, path: P) -> Result<(), ParaglobError> {
    let mut file = File::create(path)?;
    file.write_all(paraglob.buffer())?;
    file.sync_all()?;
    Ok(())
}

/// Load a Paraglob from a file
///
/// Uses memory mapping for instant loading with zero data copying.
/// Multiple processes loading the same file will share physical memory.
///
/// # Performance
///
/// - **Load time**: ~1ms regardless of file size (just mmap syscall)
/// - **Memory usage**: Pages loaded on-demand by OS
/// - **Shared memory**: Multiple processes share the same physical RAM
///
/// # Example
///
/// ```no_run
/// use matchy::MatchMode;
/// use matchy::serialization::load;
///
/// let mut pg = load("patterns.mxy", MatchMode::CaseSensitive).unwrap();
/// let matches = pg.paraglob_mut().find_all("test.txt");
/// ```
///
/// **Note:** This is a low-level API for standalone pattern files. Most users should
/// use the unified `Database::open()` API instead.
pub fn load<P: AsRef<Path>>(
    path: P,
    mode: GlobMatchMode,
) -> Result<MmappedParaglob, ParaglobError> {
    let file = File::open(path.as_ref())
        .map_err(|e| ParaglobError::Io(format!("Failed to open file: {}", e)))?;

    let mmap = unsafe {
        Mmap::map(&file).map_err(|e| ParaglobError::Mmap(format!("Failed to mmap file: {}", e)))?
    };

    // SAFETY: The mmap will remain valid because we store it in MmappedParaglob.
    // The slice will be valid for the 'static lifetime from the Paraglob's
    // perspective because MmappedParaglob ensures the mmap outlives the Paraglob.
    let slice: &'static [u8] = unsafe { std::slice::from_raw_parts(mmap.as_ptr(), mmap.len()) };

    let paraglob = unsafe { Paraglob::from_mmap(slice, mode)? };

    Ok(MmappedParaglob { mmap, paraglob })
}

/// Convert a Paraglob to bytes
///
/// Returns a byte vector that can be transmitted over network,
/// embedded in executables, or stored elsewhere.
///
/// # Example
///
/// ```
/// use matchy::paraglob_offset::Paraglob;
/// use matchy::MatchMode;
/// use matchy::serialization::to_bytes;
///
/// let patterns = vec!["*.txt"];
/// let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();
/// let bytes = to_bytes(&pg);
///
/// // Send over network, embed in binary, etc.
/// assert!(!bytes.is_empty());
/// ```
pub fn to_bytes(paraglob: &Paraglob) -> Vec<u8> {
    paraglob.buffer().to_vec()
}

/// Create a Paraglob from bytes
///
/// Useful for loading from network, embedded data, or other sources.
///
/// # Example
///
/// ```
/// use matchy::paraglob_offset::Paraglob;
/// use matchy::MatchMode;
/// use matchy::serialization::{to_bytes, from_bytes};
///
/// let patterns = vec!["*.txt"];
/// let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();
/// let bytes = to_bytes(&pg);
///
/// // Later, possibly in different process
/// let pg2 = from_bytes(&bytes, MatchMode::CaseSensitive).unwrap();
/// assert_eq!(pg.pattern_count(), pg2.pattern_count());
/// ```
pub fn from_bytes(data: &[u8], mode: GlobMatchMode) -> Result<Paraglob, ParaglobError> {
    Paraglob::from_buffer(data.to_vec(), mode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_bytes_roundtrip() {
        let patterns = vec!["hello", "*.txt", "test_*"];
        let pg = Paraglob::build_from_patterns(&patterns, GlobMatchMode::CaseSensitive).unwrap();

        let bytes = to_bytes(&pg);
        let pg2 = from_bytes(&bytes, GlobMatchMode::CaseSensitive).unwrap();

        assert_eq!(pg.pattern_count(), pg2.pattern_count());
    }

    #[test]
    fn test_file_roundtrip() {
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("paraglob_test_file_roundtrip.pgb");

        let patterns = vec!["hello", "*.txt", "test_*"];
        let pg = Paraglob::build_from_patterns(&patterns, GlobMatchMode::CaseSensitive).unwrap();

        // Save
        save(&pg, &path).unwrap();

        // Load
        let mut pg_loaded = load(&path, GlobMatchMode::CaseSensitive).unwrap();

        // Test matching produces same results
        let text = "hello test_file.txt";
        let expected = pg.find_all(text);
        let actual = pg_loaded.paraglob_mut().find_all(text);
        assert_eq!(expected, actual);

        // Cleanup
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_shared_memory_simulation() {
        // Simulate multiple processes loading same file
        // OS shares physical memory pages between all loads
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("paraglob_test_shared_memory.pgb");

        let patterns = vec!["hello", "*.txt", "test_*"];
        let pg = Paraglob::build_from_patterns(&patterns, GlobMatchMode::CaseSensitive).unwrap();
        save(&pg, &path).unwrap();

        // Load multiple times (simulates multiple processes)
        let mut pg1 = load(&path, GlobMatchMode::CaseSensitive).unwrap();
        let mut pg2 = load(&path, GlobMatchMode::CaseSensitive).unwrap();
        let mut pg3 = load(&path, GlobMatchMode::CaseSensitive).unwrap();

        // All should produce identical results
        let text = "hello.txt";
        let m1 = pg1.paraglob_mut().find_all(text);
        let m2 = pg2.paraglob_mut().find_all(text);
        let m3 = pg3.paraglob_mut().find_all(text);

        assert_eq!(m1, m2);
        assert_eq!(m2, m3);
        assert_eq!(m1.len(), 2);

        // Cleanup
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_instant_loading() {
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("paraglob_test_instant_loading.pgb");

        // Create a pattern database
        let patterns: Vec<String> = (0..1000).map(|i| format!("pattern_{}_*.txt", i)).collect();
        let pattern_refs: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();

        let pg =
            Paraglob::build_from_patterns(&pattern_refs, GlobMatchMode::CaseSensitive).unwrap();
        save(&pg, &path).unwrap();

        // Loading should be instant (just mmap syscall)
        let start = std::time::Instant::now();
        let _pg_loaded = load(&path, GlobMatchMode::CaseSensitive).unwrap();
        let elapsed = start.elapsed();

        // Should be very fast (< 100ms) even for large files
        // This is still orders of magnitude faster than deserialization
        assert!(
            elapsed.as_millis() < 100,
            "Load took {}ms, expected < 100ms",
            elapsed.as_millis()
        );

        // Cleanup
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_nonexistent_file() {
        let result = load("/nonexistent/file.pgb", GlobMatchMode::CaseSensitive);
        assert!(result.is_err());
    }
}
