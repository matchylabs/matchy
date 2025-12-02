//! Batch processing infrastructure for efficient file analysis
//!
//! General-purpose building blocks for sequential or parallel processing:
//! - **DataBatch**: Pre-chunked raw byte data
//! - **FileReader**: Chunks files efficiently with gzip support
//! - **Worker**: Processes batches with extraction + database matching
//! - **MatchResult**: Core match info with source context
//!
//! # Sequential Example
//!
//! ```rust,no_run
//! use matchy::{Database, processing};
//! use matchy::extractor::Extractor;
//! use std::sync::Arc;
//!
//! let db = Database::from("threats.mxy").open()?;
//! let extractor = Extractor::new()?;
//!
//! let mut worker = processing::Worker::builder()
//!     .extractor(extractor)
//!     .add_database("threats", Arc::new(db))
//!     .build();
//!
//! let reader = processing::FileReader::new("access.log.gz", 128 * 1024)?;
//! for batch in reader.batches() {
//!     let batch = batch?;
//!     let matches = worker.process_batch(&batch)?;
//!     for m in matches {
//!         println!("{} - {}", m.source.display(), m.matched_text);
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Parallel Example (native platforms only)
//!
//! ```text
//! Reader Thread → [DataBatch queue] → Worker Pool → [Result queue] → Output Thread
//! ```
//!
//! Use [`process_files_parallel`] for multi-threaded file processing on native platforms.

use crate::extractor::{ExtractedItem, Extractor, HashType};
use crate::{Database, QueryResult};
use std::io::{self, BufRead, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

// Parallel processing module (native platforms only)
#[cfg(not(target_family = "wasm"))]
mod parallel;

#[cfg(not(target_family = "wasm"))]
pub use parallel::{process_files_parallel, ParallelProcessingResult, RoutingStats};

/// A unit of work that can be processed independently
///
/// Work units can represent either entire files or pre-chunked data.
/// The parallel processor uses these to distribute work efficiently.
#[derive(Clone)]
pub enum WorkUnit {
    /// Entire file - worker opens, reads, and processes
    WholeFile {
        /// Path to the file to process
        path: PathBuf,
    },

    /// Pre-chunked data - worker processes directly
    Chunk {
        /// Pre-chunked batch ready for processing
        batch: DataBatch,
    },
}

/// Pre-chunked batch of raw data ready for parallel processing
#[derive(Clone)]
pub struct DataBatch {
    /// Source file path
    pub source: PathBuf,
    /// Raw byte data for this batch
    pub data: Arc<Vec<u8>>,
}

/// Statistics from batch processing
#[derive(Default, Clone, Debug)]
pub struct WorkerStats {
    /// Total lines processed
    pub lines_processed: usize,
    /// Total candidates extracted and tested
    pub candidates_tested: usize,
    /// Total matches found
    pub matches_found: usize,
    /// Total bytes processed
    pub total_bytes: usize,
    /// Time spent extracting candidates (sampled)
    pub extraction_time: std::time::Duration,
    /// Number of extraction samples
    pub extraction_samples: usize,
    /// Time spent on database lookups (sampled)
    pub lookup_time: std::time::Duration,
    /// Number of lookup samples
    pub lookup_samples: usize,
    /// IPv4 addresses found
    pub ipv4_count: usize,
    /// IPv6 addresses found
    pub ipv6_count: usize,
    /// Domain names found
    pub domain_count: usize,
    /// Email addresses found
    pub email_count: usize,
    /// MD5 hashes found
    pub md5_count: usize,
    /// SHA1 hashes found
    pub sha1_count: usize,
    /// SHA256 hashes found
    pub sha256_count: usize,
    /// SHA384 hashes found
    pub sha384_count: usize,
    /// SHA512 hashes found
    pub sha512_count: usize,
    /// Bitcoin addresses found
    pub bitcoin_count: usize,
    /// Ethereum addresses found
    pub ethereum_count: usize,
    /// Monero addresses found
    pub monero_count: usize,
}

/// Match result with source context
#[derive(Clone, Debug)]
pub struct MatchResult {
    /// Matched text
    pub matched_text: String,
    /// Type of match (e.g., "IPv4", "IPv6", "Domain", "Email")
    pub match_type: String,
    /// Query result from database
    pub result: QueryResult,
    /// Which database matched (database ID)
    pub database_id: String,
    /// Source label (file path, "-" for stdin, or any label)
    pub source: PathBuf,
    /// Byte offset in the input data (0-indexed)
    pub byte_offset: usize,
}

/// Reads files in chunks with compression support
///
/// Efficiently chunks files by reading fixed-size blocks.
/// Splits on newline boundaries to avoid breaking lines across batches.
/// Supports gzip-compressed files via extension detection.
pub struct FileReader {
    source_path: PathBuf,
    reader: Box<dyn BufRead + Send>,
    read_buffer: Vec<u8>,
    eof: bool,
    leftover: Vec<u8>, // Partial line from previous read
}

impl FileReader {
    /// Create a new chunking reader
    ///
    /// # Arguments
    ///
    /// * `path` - File to read (supports .gz compression)
    /// * `chunk_size` - Target chunk size in bytes (typically 128KB)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use matchy::processing::FileReader;
    ///
    /// let reader = FileReader::new("access.log.gz", 128 * 1024)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn new<P: AsRef<Path>>(path: P, chunk_size: usize) -> io::Result<Self> {
        let path = path.as_ref();

        // Open with automatic decompression
        let reader = crate::file_reader::open(path)?;

        Ok(Self {
            source_path: path.to_path_buf(),
            reader,
            read_buffer: vec![0u8; chunk_size],
            eof: false,
            leftover: Vec::with_capacity(chunk_size),
        })
    }

    /// Read next batch of data
    ///
    /// Returns `None` when EOF is reached.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use matchy::processing::FileReader;
    /// let mut reader = FileReader::new("data.log", 128 * 1024)?;
    ///
    /// while let Some(batch) = reader.next_batch()? {
    ///     println!("Batch has {} bytes", batch.data.len());
    /// }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn next_batch(&mut self) -> io::Result<Option<DataBatch>> {
        if self.eof {
            return Ok(None);
        }

        // Read a chunk - BufReader underneath handles syscall batching efficiently
        let bytes_read = self.reader.read(&mut self.read_buffer)?;

        if bytes_read == 0 {
            self.eof = true;
            // Send any leftover data from previous reads
            if !self.leftover.is_empty() {
                let chunk = std::mem::take(&mut self.leftover);
                return Ok(Some(DataBatch {
                    source: self.source_path.clone(),
                    data: Arc::new(chunk),
                }));
            }
            return Ok(None);
        }

        // Combine with leftover from previous read
        let mut combined = std::mem::take(&mut self.leftover);
        combined.extend_from_slice(&self.read_buffer[..bytes_read]);

        // Find last newline to split on line boundary
        let chunk_end = if let Some(pos) = memchr::memrchr(b'\n', &combined) {
            pos + 1 // Include the newline
        } else {
            // No newline found - save for next read
            self.leftover = combined;
            return self.next_batch(); // Try to read more
        };

        // Split at last newline
        let mut chunk = combined;
        if chunk_end < chunk.len() {
            self.leftover = chunk.split_off(chunk_end);
        }
        chunk.truncate(chunk_end);

        Ok(Some(DataBatch {
            source: self.source_path.clone(),
            data: Arc::new(chunk),
        }))
    }

    /// Returns an iterator over data batches
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use matchy::processing::FileReader;
    /// let reader = FileReader::new("data.log", 128 * 1024)?;
    ///
    /// for batch in reader.batches() {
    ///     let batch = batch?;
    ///     // Process batch...
    /// }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn batches(self) -> DataBatchIter {
        DataBatchIter { reader: self }
    }
}

/// Iterator over data batches
pub struct DataBatchIter {
    reader: FileReader,
}

impl Iterator for DataBatchIter {
    type Item = io::Result<DataBatch>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.next_batch() {
            Ok(Some(batch)) => Some(Ok(batch)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

/// Worker that processes batches with extraction + database matching
///
/// Supports multiple databases for cross-referencing threat feeds, allowlists, etc.
/// Use [`WorkerBuilder`] to construct workers.
///
/// # Example
///
/// ```rust,no_run
/// use matchy::{Database, processing};
/// use matchy::extractor::Extractor;
/// use std::sync::Arc;
///
/// let db = Database::from("threats.mxy").open()?;
/// let extractor = Extractor::new()?;
///
/// let mut worker = processing::Worker::builder()
///     .extractor(extractor)
///     .add_database("threats", Arc::new(db))
///     .build();
///
/// // Process raw bytes
/// let matches = worker.process_bytes(b"Check 192.168.1.1")?;
/// println!("Found {} matches", matches.len());
///
/// // Check statistics
/// let stats = worker.stats();
/// println!("Processed {} candidates", stats.candidates_tested);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct Worker {
    extractor: Extractor,
    databases: Vec<(String, Arc<Database>)>, // (database_id, database)
    stats: WorkerStats,
}

impl Worker {
    /// Create a worker builder
    pub fn builder() -> WorkerBuilder {
        WorkerBuilder::new()
    }

    /// Process raw bytes without line tracking
    ///
    /// Returns core match results without file/line context.
    /// Useful for non-file processing (matchy-app, streaming, etc.)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use matchy::{Database, processing};
    /// # use matchy::extractor::Extractor;
    /// # use std::sync::Arc;
    /// # let db = Database::from("db.mxy").open()?;
    /// # let extractor = Extractor::new()?;
    /// # let mut worker = processing::Worker::builder()
    /// #     .extractor(extractor).add_database("db", Arc::new(db)).build();
    /// let text = "Check 192.168.1.1";
    /// let matches = worker.process_bytes(text.as_bytes())?;
    ///
    /// for m in matches {
    ///     println!("{} found in {}", m.matched_text, m.database_id);
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn process_bytes(&mut self, data: &[u8]) -> Result<Vec<MatchResult>, String> {
        let mut results = Vec::new();

        // Update stats - count lines efficiently without allocating
        self.stats.lines_processed += memchr::memchr_iter(b'\n', data).count();
        self.stats.total_bytes += data.len();

        // Sample timing every 1000 operations to avoid overhead
        let should_sample_extraction = self.stats.extraction_samples < 100_000
            && self.stats.candidates_tested.is_multiple_of(1000);

        // Extract all candidates in one pass
        let extraction_start = if should_sample_extraction {
            Some(Instant::now())
        } else {
            None
        };

        let extracted = self.extractor.extract_from_chunk(data);

        if let Some(start) = extraction_start {
            self.stats.extraction_time += start.elapsed();
            self.stats.extraction_samples += 1;
        }

        for item in extracted {
            self.stats.candidates_tested += 1;

            // Track candidate types
            match &item.item {
                ExtractedItem::Ipv4(_) => self.stats.ipv4_count += 1,
                ExtractedItem::Ipv6(_) => self.stats.ipv6_count += 1,
                ExtractedItem::Domain(_) => self.stats.domain_count += 1,
                ExtractedItem::Email(_) => self.stats.email_count += 1,
                ExtractedItem::Hash(hash_type, _) => match hash_type {
                    HashType::Md5 => self.stats.md5_count += 1,
                    HashType::Sha1 => self.stats.sha1_count += 1,
                    HashType::Sha256 => self.stats.sha256_count += 1,
                    HashType::Sha384 => self.stats.sha384_count += 1,
                    HashType::Sha512 => self.stats.sha512_count += 1,
                },
                ExtractedItem::Bitcoin(_) => self.stats.bitcoin_count += 1,
                ExtractedItem::Ethereum(_) => self.stats.ethereum_count += 1,
                ExtractedItem::Monero(_) => self.stats.monero_count += 1,
            }

            // Sample lookup timing every 100 lookups
            let should_sample_lookup = self.stats.lookup_samples < 100_000
                && self.stats.candidates_tested.is_multiple_of(100);

            // Lookup in all databases
            for (database_id, database) in &self.databases {
                let lookup_start = if should_sample_lookup {
                    Some(Instant::now())
                } else {
                    None
                };

                // Use lookup_extracted for optimal performance:
                // - IP addresses use typed lookup (no string parsing)
                // - Other types use string lookup
                let result_opt = database
                    .lookup_extracted(&item, data)
                    .map_err(|e| e.to_string())?;

                if let Some(start) = lookup_start {
                    self.stats.lookup_time += start.elapsed();
                    self.stats.lookup_samples += 1;
                }

                if let Some(query_result) = result_opt {
                    // Skip QueryResult::NotFound - not a real match
                    if matches!(query_result, crate::QueryResult::NotFound) {
                        continue;
                    }

                    self.stats.matches_found += 1;

                    // Only stringify when we have a match - extract original text from input
                    // Use Match::as_str() which safely extracts the text using validated spans
                    let matched_text = item.as_str(data).to_string();

                    results.push(MatchResult {
                        matched_text,
                        match_type: item.item.type_name().to_string(),
                        result: query_result,
                        database_id: database_id.clone(),
                        source: PathBuf::from(""), // Will be filled by process_batch()
                        byte_offset: item.span.0,
                    });
                }
            }
        }

        Ok(results)
    }

    /// Process a batch with source context
    ///
    /// Returns matches with source path filled in.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use matchy::{Database, processing};
    /// # use matchy::extractor::Extractor;
    /// # use std::sync::Arc;
    /// # let db = Database::from("db.mxy").open()?;
    /// # let extractor = Extractor::new()?;
    /// # let mut worker = processing::Worker::builder()
    /// #     .extractor(extractor).add_database("db", Arc::new(db)).build();
    /// # let reader = processing::FileReader::new("data.log", 128*1024)?;
    /// # let batch = reader.batches().next().unwrap()?;
    /// let matches = worker.process_batch(&batch)?;
    ///
    /// for m in matches {
    ///     println!("{} - {}", m.source.display(), m.matched_text);
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn process_batch(&mut self, batch: &DataBatch) -> Result<Vec<MatchResult>, String> {
        // Get core match results
        let mut match_results = self.process_bytes(&batch.data)?;

        // Fill in source path for all matches
        for m in &mut match_results {
            m.source = batch.source.clone();
        }

        Ok(match_results)
    }

    /// Get accumulated statistics
    ///
    /// Returns statistics for all batches processed by this worker.
    pub fn stats(&self) -> &WorkerStats {
        &self.stats
    }

    /// Reset statistics to zero
    pub fn reset_stats(&mut self) {
        self.stats = WorkerStats::default();
    }
}

/// Builder for [`Worker`] with support for multiple databases
///
/// # Example
///
/// ```rust,no_run
/// use matchy::{Database, processing};
/// use matchy::extractor::Extractor;
/// use std::sync::Arc;
///
/// let threats = Database::from("threats.mxy").open()?;
/// let allowlist = Database::from("allowlist.mxy").open()?;
/// let extractor = Extractor::new()?;
///
/// let worker = processing::Worker::builder()
///     .extractor(extractor)
///     .add_database("threats", Arc::new(threats))
///     .add_database("allowlist", Arc::new(allowlist))
///     .build();
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct WorkerBuilder {
    extractor: Option<Extractor>,
    databases: Vec<(String, Arc<Database>)>,
}

impl WorkerBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            extractor: None,
            databases: Vec::new(),
        }
    }

    /// Set the pattern extractor
    pub fn extractor(mut self, extractor: Extractor) -> Self {
        self.extractor = Some(extractor);
        self
    }

    /// Add a database with an identifier
    ///
    /// The identifier is included in match results to show which database matched.
    /// The database is wrapped in Arc for efficient sharing across workers.
    pub fn add_database(mut self, id: impl Into<String>, database: Arc<Database>) -> Self {
        self.databases.push((id.into(), database));
        self
    }

    /// Build the worker
    ///
    /// # Panics
    ///
    /// Panics if extractor was not set or no databases were added.
    pub fn build(self) -> Worker {
        let extractor = self
            .extractor
            .expect("Extractor not set - call .extractor()");
        assert!(
            !self.databases.is_empty(),
            "No databases added - call .add_database() at least once"
        );

        Worker {
            extractor,
            databases: self.databases,
            stats: WorkerStats::default(),
        }
    }
}

impl Default for WorkerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_file_reader_basic() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "line 1").unwrap();
        writeln!(file, "line 2").unwrap();
        writeln!(file, "line 3").unwrap();
        file.flush().unwrap();

        let mut reader = FileReader::new(file.path(), 1024).unwrap();
        let batch = reader.next_batch().unwrap().unwrap();

        // Verify batch contains data and source
        assert!(!batch.data.is_empty());
        assert_eq!(batch.source, file.path());
    }

    #[test]
    fn test_batch_iter() {
        let mut file = NamedTempFile::new().unwrap();
        for i in 1..=10 {
            writeln!(file, "line {}", i).unwrap();
        }
        file.flush().unwrap();

        let reader = FileReader::new(file.path(), 1024).unwrap();
        let batches: Vec<_> = reader.batches().collect::<io::Result<Vec<_>>>().unwrap();

        assert!(!batches.is_empty());
        // Verify we got data from all batches
        let total_bytes: usize = batches.iter().map(|b| b.data.len()).sum();
        assert!(total_bytes > 0);
    }

    #[test]
    fn test_worker_process_bytes() {
        use crate::extractor::Extractor;
        use crate::{DatabaseBuilder, MatchMode};
        use std::collections::HashMap;

        // Create a simple database with one IP
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut data = HashMap::new();
        data.insert(
            "type".to_string(),
            crate::DataValue::String("threat".to_string()),
        );
        builder.add_ip("1.2.3.4", data).unwrap();

        let db_bytes = builder.build().unwrap();
        let mut tmpfile = NamedTempFile::new().unwrap();
        tmpfile.write_all(&db_bytes).unwrap();
        tmpfile.flush().unwrap();

        let db = crate::Database::from(tmpfile.path().to_str().unwrap())
            .open()
            .unwrap();
        let extractor = Extractor::new().unwrap();

        let mut worker = Worker::builder()
            .extractor(extractor)
            .add_database("test", Arc::new(db))
            .build();

        // Process bytes containing an IP
        let input = b"Connection from 1.2.3.4 detected";
        let matches = worker.process_bytes(input).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched_text, "1.2.3.4");
        assert_eq!(matches[0].match_type, "IPv4");

        // Check stats
        let stats = worker.stats();
        assert_eq!(stats.matches_found, 1);
        assert!(stats.candidates_tested > 0);
    }

    #[test]
    fn test_worker_process_batch() {
        use crate::extractor::Extractor;
        use crate::{DatabaseBuilder, MatchMode};
        use std::collections::HashMap;

        // Create a database with multiple entries
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let data = HashMap::new();
        builder.add_ip("8.8.8.8", data.clone()).unwrap();
        builder.add_literal("evil.com", data).unwrap();

        let db_bytes = builder.build().unwrap();
        let mut tmpfile = NamedTempFile::new().unwrap();
        tmpfile.write_all(&db_bytes).unwrap();
        tmpfile.flush().unwrap();

        let db = crate::Database::from(tmpfile.path().to_str().unwrap())
            .open()
            .unwrap();
        let extractor = Extractor::new().unwrap();

        let mut worker = Worker::builder()
            .extractor(extractor)
            .add_database("test", Arc::new(db))
            .build();

        // Create a batch
        let batch = DataBatch {
            source: PathBuf::from("test.log"),
            data: Arc::new(b"DNS query to evil.com from 8.8.8.8".to_vec()),
        };

        let matches = worker.process_batch(&batch).unwrap();

        // Should find both matches
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().any(|m| m.matched_text == "8.8.8.8"));
        assert!(matches.iter().any(|m| m.matched_text == "evil.com"));

        // Source path should be set
        for m in &matches {
            assert_eq!(m.source, PathBuf::from("test.log"));
        }
    }
}
