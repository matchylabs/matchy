//! Memory-mapped file support for paraglob files.
//!
//! This module provides safe, validated access to memory-mapped paraglob files.
//! It handles file opening, header validation, and provides safe accessors to
//! the underlying data structures.
//!
//! # Safety
//!
//! While memory-mapped files are inherently unsafe (file contents can change),
//! this module provides a safe API by:
//! - Validating all headers on open
//! - Checking file size constraints
//! - Using safe Rust types for all public APIs
//! - Providing bounds-checked accessors
//!
//! # Example
//!
//! ```no_run
//! use matchy::mmap::MmapFile;
//!
//! let mmap = MmapFile::open("database.paraglob")?;
//! let header = mmap.paraglob_header();
//! println!("Magic: {:?}", &header.magic);
//! println!("Size: {} bytes", mmap.size());
//! # Ok::<(), matchy::mmap::MmapError>(())
//! ```

use crate::offset_format::{ParaglobHeader, MAGIC, MATCHY_FORMAT_VERSION};
use memmap2::Mmap;
use std::fmt;
use std::fs::File;
use std::io;
use std::mem;
use std::path::Path;

/// Validate a Paraglob header from a buffer
fn validate_paraglob_header(buffer: &[u8]) -> Result<&ParaglobHeader, String> {
    // Check buffer size
    if buffer.len() < mem::size_of::<ParaglobHeader>() {
        return Err(format!(
            "Buffer too small: need {} bytes, got {}",
            mem::size_of::<ParaglobHeader>(),
            buffer.len()
        ));
    }

    // Cast to header (safe because we validated size)
    let header = unsafe { &*(buffer.as_ptr() as *const ParaglobHeader) };

    // Check magic bytes
    if &header.magic != MAGIC {
        return Err(format!(
            "Invalid magic bytes: expected {:?}, found {:?}",
            std::str::from_utf8(MAGIC).unwrap_or("???"),
            std::str::from_utf8(&header.magic).unwrap_or("???")
        ));
    }

    // Check version
    if header.version != MATCHY_FORMAT_VERSION {
        return Err(format!(
            "Unsupported format version: found {}, supported {}",
            header.version, MATCHY_FORMAT_VERSION
        ));
    }

    // Check total buffer size
    if header.total_buffer_size as usize != buffer.len() {
        return Err("Header buffer size doesn't match actual buffer".to_string());
    }

    Ok(header)
}

/// Errors that can occur when working with memory-mapped files.
#[derive(Debug)]
pub enum MmapError {
    /// Failed to open the file
    Io(io::Error),
    /// File is too small to contain a valid header
    FileTooSmall {
        /// Actual file size in bytes
        size: usize,
        /// Minimum required size in bytes
        required: usize,
    },
    /// Invalid Paraglob header
    InvalidParaglobHeader(String),
}

impl fmt::Display for MmapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MmapError::Io(e) => write!(f, "I/O error: {}", e),
            MmapError::FileTooSmall { size, required } => {
                write!(
                    f,
                    "File too small: {} bytes (need at least {})",
                    size, required
                )
            }
            MmapError::InvalidParaglobHeader(msg) => write!(f, "Invalid Paraglob header: {}", msg),
        }
    }
}

impl std::error::Error for MmapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MmapError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for MmapError {
    fn from(err: io::Error) -> Self {
        MmapError::Io(err)
    }
}

/// A memory-mapped paraglob file with validated headers.
///
/// This type provides safe, validated access to a memory-mapped paraglob file.
/// The file is automatically unmapped when the `MmapFile` is dropped.
///
/// # Thread Safety
///
/// `MmapFile` is `Send` but not `Sync`. Multiple threads can own separate
/// `MmapFile` instances, but a single instance should not be shared across
/// threads without synchronization.
pub struct MmapFile {
    /// The memory-mapped file
    mmap: Mmap,
    /// Size of the mapped region
    size: usize,
}

impl MmapFile {
    /// Open and memory-map a paraglob file.
    ///
    /// This function:
    /// 1. Opens the file
    /// 2. Memory-maps it
    /// 3. Validates the Paraglob header
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be opened
    /// - The file is too small
    /// - The Paraglob header is invalid
    ///
    /// # Example
    ///
    /// ```no_run
    /// use matchy::mmap::MmapFile;
    ///
    /// let mmap = MmapFile::open("database.paraglob")?;
    /// # Ok::<(), matchy::mmap::MmapError>(())
    /// ```
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, MmapError> {
        let file = File::open(path.as_ref())?;
        let mmap = unsafe { Mmap::map(&file)? };
        let size = mmap.len();

        // Check minimum size for Paraglob header
        let min_size = std::mem::size_of::<ParaglobHeader>();
        if size < min_size {
            return Err(MmapError::FileTooSmall {
                size,
                required: min_size,
            });
        }

        // Validate Paraglob header
        let buffer = &mmap[..];
        validate_paraglob_header(buffer)
            .map_err(|e| MmapError::InvalidParaglobHeader(e.to_string()))?;

        // Apply platform-specific memory optimizations
        #[cfg(unix)]
        unsafe {
            Self::optimize_mmap(&mmap, size);
        }

        Ok(MmapFile { mmap, size })
    }

    /// Apply platform-specific memory optimizations.
    ///
    /// Optimizations by platform:
    /// - **macOS**: Uses 16K pages automatically on Apple Silicon
    /// - **Linux**: Hints for 2MB transparent huge pages (THP)
    /// - **All Unix**: Memory locking and prefetching
    ///
    /// # Safety
    ///
    /// Caller must ensure the mmap pointer and size are valid.
    #[cfg(unix)]
    unsafe fn optimize_mmap(mmap: &Mmap, size: usize) {
        use libc::{madvise, mlock, MADV_RANDOM};

        let ptr = mmap.as_ptr() as *mut libc::c_void;

        // Linux-specific: request transparent huge pages (2MB)
        #[cfg(target_os = "linux")]
        {
            const MADV_HUGEPAGE: libc::c_int = 14;
            madvise(ptr, size, MADV_HUGEPAGE);
        }

        // FreeBSD: Supports MADV_NOSYNC for better performance with mmap
        #[cfg(target_os = "freebsd")]
        {
            // MADV_NOSYNC tells kernel not to sync changes back to disk
            // (we're read-only anyway)
            madvise(ptr, size, libc::MADV_NOSYNC);
        }

        // macOS with Apple Silicon automatically uses 16K pages for file mappings
        // when the size and alignment are appropriate. No explicit hint needed.

        // Don't prefetch - let OS lazily load pages on demand.
        // MADV_WILLNEED would force synchronous I/O at mmap time, which:
        // - Blocks the thread
        // - Loads entire file even if we only need part of it
        // - Shows up as mmap() time in profilers
        //
        // Instead, use MADV_RANDOM to disable readahead since our access
        // pattern is unpredictable (hash lookups, trie traversal, etc.)
        madvise(ptr, size, MADV_RANDOM);

        // Try to lock pages in RAM (requires elevated permissions)
        // Only do this if the file is small enough to be reasonable.
        // Falls back gracefully if permission denied or file too large.
        const MAX_MLOCK_SIZE: usize = 256 * 1024 * 1024; // 256MB
        if size <= MAX_MLOCK_SIZE {
            let _ = mlock(ptr, size); // Ignore errors - mlock is best-effort
        }
    }

    /// Get a reference to the Paraglob header.
    ///
    /// # Safety
    ///
    /// This is safe because we validated the header in `open()`.
    pub fn paraglob_header(&self) -> &ParaglobHeader {
        unsafe {
            // SAFETY: We validated this in open() and the size cannot change
            &*(self.mmap.as_ptr() as *const ParaglobHeader)
        }
    }

    /// Get the size of the memory-mapped file in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get a slice of the entire mapped memory.
    ///
    /// # Safety
    ///
    /// While this function is safe to call, the contents of a memory-mapped file
    /// can theoretically change if another process modifies the file. However,
    /// this is unlikely in practice and the returned slice is still memory-safe.
    pub fn as_slice(&self) -> &[u8] {
        &self.mmap[..]
    }

    /// Get a slice at a specific offset with bounds checking.
    ///
    /// Returns `None` if the offset + length would exceed the file size.
    pub fn get_slice(&self, offset: usize, length: usize) -> Option<&[u8]> {
        if offset.checked_add(length)? > self.size {
            return None;
        }
        Some(&self.mmap[offset..offset + length])
    }
}

impl fmt::Debug for MmapFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MmapFile")
            .field("size", &self.size)
            .field("header", &self.paraglob_header())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_file(data: &[u8]) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(data).unwrap();
        file.flush().unwrap();
        file
    }

    #[test]
    fn test_empty_file() {
        let file = create_test_file(&[]);
        let result = MmapFile::open(file.path());
        assert!(matches!(result, Err(MmapError::FileTooSmall { .. })));
    }

    #[test]
    fn test_file_too_small() {
        let file = create_test_file(&[0; 10]);
        let result = MmapFile::open(file.path());
        assert!(matches!(result, Err(MmapError::FileTooSmall { .. })));
    }

    #[test]
    fn test_invalid_magic() {
        // Create a header with wrong magic bytes
        let mut header = ParaglobHeader::new();
        header.magic = *b"XXXXXXXX"; // Invalid magic
        header.total_buffer_size = std::mem::size_of::<ParaglobHeader>() as u32;

        let mut data = vec![0u8; std::mem::size_of::<ParaglobHeader>()];
        unsafe {
            let ptr = data.as_mut_ptr() as *mut ParaglobHeader;
            ptr.write(header);
        }

        let file = create_test_file(&data);
        let result = MmapFile::open(file.path());
        assert!(matches!(result, Err(MmapError::InvalidParaglobHeader(_))));
    }

    #[test]
    fn test_valid_paraglob_header() {
        let mut header = ParaglobHeader::new();
        header.total_buffer_size = std::mem::size_of::<ParaglobHeader>() as u32;

        // Serialize header to bytes
        let mut data = vec![0u8; std::mem::size_of::<ParaglobHeader>()];
        unsafe {
            let ptr = data.as_mut_ptr() as *mut ParaglobHeader;
            ptr.write(header);
        }

        let file = create_test_file(&data);
        let mmap = MmapFile::open(file.path()).expect("Failed to open valid Paraglob file");
        assert_eq!(mmap.size(), data.len());
        assert_eq!(mmap.paraglob_header().magic, *MAGIC);
        assert_eq!(mmap.paraglob_header().version, MATCHY_FORMAT_VERSION);
    }

    #[test]
    fn test_get_slice() {
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let header_size = std::mem::size_of::<ParaglobHeader>();
        let total_size = header_size + payload.len();

        // Create valid Paraglob header
        let mut header = ParaglobHeader::new();
        header.total_buffer_size = total_size as u32;

        let mut data = vec![0u8; header_size];
        unsafe {
            let ptr = data.as_mut_ptr() as *mut ParaglobHeader;
            ptr.write(header);
        }
        data.extend_from_slice(&payload);

        let file = create_test_file(&data);
        let mmap = MmapFile::open(file.path()).unwrap();

        // Valid slice
        let offset = header_size;
        let slice = mmap.get_slice(offset, 4).unwrap();
        assert_eq!(slice, &[1, 2, 3, 4]);

        // Out of bounds
        assert!(mmap.get_slice(mmap.size(), 1).is_none());
        assert!(mmap.get_slice(0, mmap.size() + 1).is_none());
    }

    #[test]
    fn test_nonexistent_file() {
        let result = MmapFile::open("/nonexistent/path/to/file.paraglob");
        assert!(matches!(result, Err(MmapError::Io(_))));
    }
}
