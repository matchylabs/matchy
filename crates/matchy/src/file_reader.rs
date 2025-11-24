//! Streaming file reader with automatic gzip decompression
//!
//! This module provides utilities for reading files with automatic detection
//! and decompression of gzip-compressed files based on file extension.
//!
//! # Example
//!
//! ```rust,no_run
//! use matchy::file_reader;
//! use std::io::BufRead;
//!
//! // Automatically detects .gz and decompresses
//! let reader = file_reader::open("access.log.gz")?;
//!
//! for line in reader.lines() {
//!     let line = line?;
//!     println!("{}", line);
//! }
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! # Integration with LineScanner
//!
//! The reader returns a `Box<dyn BufRead>` that works seamlessly with matchy's
//! zero-copy `LineScanner` for maximum performance:
//!
//! ```rust,no_run
//! # fn example() -> std::io::Result<()> {
//! # use matchy::file_reader;
//! // In your CLI or app code:
//! let reader = file_reader::open("logfile.txt.gz")?;
//! // Use with LineScanner for zero-copy line iteration
//! # Ok(())
//! # }
//! ```

use flate2::read::GzDecoder;
use std::fs::File;
use std::io::{self, stdin, BufRead, BufReader};
use std::path::Path;

/// Buffer size for file reading (128KB, matches CLI default)
const BUFFER_SIZE: usize = 128 * 1024;

/// Open a file with automatic gzip detection based on file extension
///
/// Files ending in `.gz` (case-insensitive) are automatically decompressed.
/// Special case: path "-" reads from stdin.
/// Returns a buffered reader ready for line-by-line access.
///
/// # Example
///
/// ```rust,no_run
/// use matchy::file_reader;
///
/// // Compressed file - auto-decompressed
/// let reader = file_reader::open("data.log.gz")?;
///
/// // Plain text file
/// let reader2 = file_reader::open("data.log")?;
///
/// // Stdin
/// let reader3 = file_reader::open("-")?;
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The file doesn't exist
/// - Permission denied
/// - Invalid gzip data (for .gz files)
pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Box<dyn BufRead + Send>> {
    let path = path.as_ref();

    // Special case: "-" means stdin
    if path.to_str() == Some("-") {
        return Ok(Box::new(BufReader::with_capacity(BUFFER_SIZE, stdin())));
    }

    let file = File::open(path)?;

    // Check if file is gzip-compressed based on extension
    let is_gzip = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("gz"))
        .unwrap_or(false);

    if is_gzip {
        // Gzip-compressed: wrap in decoder then buffer
        let decoder = GzDecoder::new(file);
        Ok(Box::new(BufReader::with_capacity(BUFFER_SIZE, decoder)))
    } else {
        // Plain text: just buffer
        Ok(Box::new(BufReader::with_capacity(BUFFER_SIZE, file)))
    }
}

/// Create a reader from an already-opened file with explicit gzip flag
///
/// Useful when you need to override extension-based detection or already
/// have an open file handle.
///
/// # Example
///
/// ```rust,no_run
/// use std::fs::File;
/// use matchy::file_reader;
///
/// let file = File::open("data.bin")?;
/// // Force gzip decompression even though extension isn't .gz
/// let reader = file_reader::from_file(file, true);
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn from_file(file: File, is_gzip: bool) -> Box<dyn BufRead + Send> {
    if is_gzip {
        let decoder = GzDecoder::new(file);
        Box::new(BufReader::with_capacity(BUFFER_SIZE, decoder))
    } else {
        Box::new(BufReader::with_capacity(BUFFER_SIZE, file))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_plain_text_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "line 1").unwrap();
        writeln!(file, "line 2").unwrap();
        writeln!(file, "line 3").unwrap();
        file.flush().unwrap();

        let reader = open(file.path()).unwrap();
        let lines: Vec<String> = reader.lines().collect::<io::Result<Vec<_>>>().unwrap();

        assert_eq!(lines, vec!["line 1", "line 2", "line 3"]);
    }

    #[test]
    fn test_gzip_file() {
        // Create a .gz file
        let mut file = NamedTempFile::with_suffix(".gz").unwrap();
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        writeln!(encoder, "compressed 1").unwrap();
        writeln!(encoder, "compressed 2").unwrap();
        let compressed_data = encoder.finish().unwrap();
        file.write_all(&compressed_data).unwrap();
        file.flush().unwrap();

        let reader = open(file.path()).unwrap();
        let lines: Vec<String> = reader.lines().collect::<io::Result<Vec<_>>>().unwrap();

        assert_eq!(lines, vec!["compressed 1", "compressed 2"]);
    }

    #[test]
    fn test_empty_file() {
        let file = NamedTempFile::new().unwrap();
        let reader = open(file.path()).unwrap();
        let lines: Vec<String> = reader.lines().collect::<io::Result<Vec<_>>>().unwrap();

        assert!(lines.is_empty());
    }

    #[test]
    fn test_from_file_explicit_gzip() {
        // Create gzip data without .gz extension
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        writeln!(encoder, "forced gzip").unwrap();
        let compressed_data = encoder.finish().unwrap();

        let mut file = NamedTempFile::with_suffix(".bin").unwrap();
        file.write_all(&compressed_data).unwrap();
        file.flush().unwrap();

        // Open and force gzip interpretation
        let file = File::open(file.path()).unwrap();
        let reader = from_file(file, true);
        let lines: Vec<String> = reader.lines().collect::<io::Result<Vec<_>>>().unwrap();

        assert_eq!(lines, vec!["forced gzip"]);
    }

    #[test]
    fn test_case_insensitive_gz_extension() {
        // Test .GZ (uppercase)
        let mut file = NamedTempFile::with_suffix(".GZ").unwrap();
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        writeln!(encoder, "upper case gz").unwrap();
        let compressed_data = encoder.finish().unwrap();
        file.write_all(&compressed_data).unwrap();
        file.flush().unwrap();

        let reader = open(file.path()).unwrap();
        let lines: Vec<String> = reader.lines().collect::<io::Result<Vec<_>>>().unwrap();

        assert_eq!(lines, vec!["upper case gz"]);
    }
}
