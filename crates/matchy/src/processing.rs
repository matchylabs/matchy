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
//! # Parallel Example
//!
//! ```text
//! Reader Thread → [DataBatch queue] → Worker Pool → [Result queue] → Output Thread
//! ```
//!
//! Build your own parallel pipeline using channels and thread pools with these primitives.

use crate::extractor::{ExtractedItem, Extractor, HashType};
use crate::{Database, QueryResult};
use crossbeam_channel::{unbounded, Sender};
use std::fs;
use std::io::{self, BufRead, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// File size thresholds for chunk size selection
const LARGE_FILE: u64 = 1024 * 1024 * 1024; // 1GB
const HUGE_FILE: u64 = 10 * 1024 * 1024 * 1024; // 10GB

// Queue management for dynamic routing
const MAX_QUEUE_PER_WORKER: usize = 2; // Keep queues very short for responsiveness

/// System state for dynamic routing decisions
///
/// Tracks real-time system utilization to make intelligent routing decisions.
/// Workers and readers update these atomics as they process work, allowing the
/// main routing thread to see near-real-time system state.
#[derive(Debug)]
struct SystemState {
    /// Current depth of worker queue (how many work units are waiting)
    worker_queue_depth: AtomicUsize,

    /// Current depth of file queue (how many files waiting to be chunked)
    reader_queue_depth: AtomicUsize,

    /// Number of files completed in the last measurement window
    files_completed_recent: AtomicUsize,

    /// Number of chunks processed in the last measurement window
    chunks_processed_recent: AtomicUsize,

    /// Timestamp of last completion (for stall detection)
    last_completion_ns: AtomicU64,

    /// Number of worker threads
    num_workers: usize,
}

impl SystemState {
    fn new(num_workers: usize, _num_readers: usize) -> Self {
        Self {
            worker_queue_depth: AtomicUsize::new(0),
            reader_queue_depth: AtomicUsize::new(0),
            files_completed_recent: AtomicUsize::new(0),
            chunks_processed_recent: AtomicUsize::new(0),
            last_completion_ns: AtomicU64::new(0),
            num_workers,
        }
    }

    /// Check if we have capacity to add more work to queues
    fn has_routing_capacity(&self) -> bool {
        let worker_depth = self.worker_queue_depth.load(Ordering::Relaxed);
        // Allow routing when queue is not full (threshold: MAX_QUEUE_PER_WORKER * num_workers)
        worker_depth < (MAX_QUEUE_PER_WORKER * self.num_workers)
    }

    /// Record a file completion
    fn record_file_completion(&self) {
        self.files_completed_recent.fetch_add(1, Ordering::Relaxed);
        self.last_completion_ns.store(
            Instant::now().elapsed().as_nanos() as u64,
            Ordering::Relaxed,
        );
    }

    /// Record a chunk processed
    fn record_chunk_processed(&self) {
        self.chunks_processed_recent.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment worker queue depth
    fn inc_worker_queue(&self) {
        self.worker_queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement worker queue depth
    fn dec_worker_queue(&self) {
        self.worker_queue_depth.fetch_sub(1, Ordering::Relaxed);
    }

    /// Increment reader queue depth
    fn inc_reader_queue(&self) {
        self.reader_queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement reader queue depth
    fn dec_reader_queue(&self) {
        self.reader_queue_depth.fetch_sub(1, Ordering::Relaxed);
    }
}

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
            Some(std::time::Instant::now())
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
                    Some(std::time::Instant::now())
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

// Parallel Processing Implementation

/// Determine appropriate chunk size based on file size and compression
///
/// Compressed files use larger chunks because:
/// - Decompression overhead is per-read operation
/// - Larger chunks mean fewer decompress->compress cycles
/// - Workers can stay busier with bigger batches
fn chunk_size_for(file_size: u64, is_compressed: bool) -> usize {
    if is_compressed {
        // Compressed: Larger chunks to amortize decompression overhead
        match file_size {
            s if s < LARGE_FILE => 4 * 1024 * 1024, // 4MB chunks
            s if s < HUGE_FILE => 16 * 1024 * 1024, // 16MB chunks
            _ => 32 * 1024 * 1024,                  // 32MB chunks for huge files
        }
    } else {
        // Uncompressed: Smaller chunks for better parallelism
        match file_size {
            s if s < LARGE_FILE => 256 * 1024, // 256KB
            s if s < HUGE_FILE => 1024 * 1024, // 1MB
            _ => 4 * 1024 * 1024,              // 4MB
        }
    }
}

/// Reader thread worker: chunks a single file and sends batches to worker queue
/// Called by reader threads in the reader pool as they pull files from the file queue
fn reader_thread_chunker(file_path: PathBuf, work_sender: &Sender<WorkUnit>) -> Result<(), String> {
    // Special handling for stdin (can't stat it)
    let is_stdin = file_path.to_str() == Some("-");

    let chunk_size = if is_stdin {
        // Use default chunk size for stdin
        256 * 1024 // 256KB
    } else {
        let metadata = fs::metadata(&file_path)
            .map_err(|e| format!("Failed to stat {}: {}", file_path.display(), e))?;
        let file_size = metadata.len();
        let is_compressed = is_file_compressed(&file_path);
        chunk_size_for(file_size, is_compressed)
    };

    let mut reader = FileReader::new(&file_path, chunk_size)
        .map_err(|e| format!("Failed to open {}: {}", file_path.display(), e))?;

    while let Some(batch) = reader
        .next_batch()
        .map_err(|e| format!("Read error in {}: {}", file_path.display(), e))?
    {
        work_sender
            .send(WorkUnit::Chunk { batch })
            .map_err(|_| "Worker channel closed")?;
    }

    Ok(())
}

/// File metadata for routing decisions
#[derive(Debug, Clone)]
struct FileInfo {
    path: PathBuf,
    size: u64,
    is_stdin: bool,
    is_compressed: bool,
}

/// Workload statistics computed from file metadata
#[derive(Debug, Clone)]
struct WorkloadStats {
    median_size: u64,
    p95_size: u64,
    #[allow(dead_code)] // Reserved for future stats reporting
    total_bytes: u64,
}

/// Statistics about file routing decisions made by the main thread
#[derive(Debug, Clone, Default)]
pub struct RoutingStats {
    /// Files sent directly to worker queue (processed as whole files)
    pub files_to_workers: usize,
    /// Files sent to reader threads for chunking
    pub files_to_readers: usize,
    /// Total bytes in files sent to workers
    pub bytes_to_workers: u64,
    /// Total bytes in files sent to readers
    pub bytes_to_readers: u64,
}

impl RoutingStats {
    /// Total number of files processed
    pub fn total_files(&self) -> usize {
        self.files_to_workers + self.files_to_readers
    }

    /// Total bytes across all files
    pub fn total_bytes(&self) -> u64 {
        self.bytes_to_workers + self.bytes_to_readers
    }
}

/// Result from parallel file processing
pub struct ParallelProcessingResult {
    /// Matches found across all files
    pub matches: Vec<MatchResult>,
    /// Statistics about how files were routed
    pub routing_stats: RoutingStats,
    /// Aggregated worker statistics
    pub worker_stats: WorkerStats,
    /// Actual number of reader threads spawned
    pub actual_readers: usize,
    /// Actual number of worker threads spawned
    pub actual_workers: usize,
}

/// Collect metadata for all files upfront
/// Detect if a file is compressed based on extension
fn is_file_compressed(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        matches!(
            ext.to_lowercase().as_str(),
            "gz" | "bz2" | "xz" | "zst" | "lz4" | "lzma" | "z"
        )
    } else {
        // Check for multi-extension like .tar.gz
        path.to_str()
            .map(|s| {
                s.ends_with(".tar.gz")
                    || s.ends_with(".tar.bz2")
                    || s.ends_with(".tar.xz")
                    || s.ends_with(".tar.zst")
            })
            .unwrap_or(false)
    }
}

fn collect_file_metadata(files: &[PathBuf]) -> Result<Vec<FileInfo>, String> {
    let mut file_infos = Vec::with_capacity(files.len());

    for path in files {
        let is_stdin = path.to_str() == Some("-");
        let size = if is_stdin {
            0 // Unknown size for stdin
        } else {
            fs::metadata(path)
                .map_err(|e| format!("Failed to stat {}: {}", path.display(), e))?
                .len()
        };
        let is_compressed = !is_stdin && is_file_compressed(path);

        file_infos.push(FileInfo {
            path: path.clone(),
            size,
            is_stdin,
            is_compressed,
        });
    }

    Ok(file_infos)
}

/// Compute workload statistics from file metadata
fn compute_workload_stats(file_infos: &[FileInfo]) -> WorkloadStats {
    let mut sizes: Vec<u64> = file_infos
        .iter()
        .filter(|f| !f.is_stdin) // Exclude stdin from stats
        .map(|f| f.size)
        .collect();

    if sizes.is_empty() {
        return WorkloadStats {
            median_size: 0,
            p95_size: 0,
            total_bytes: 0,
        };
    }

    sizes.sort_unstable();

    let median_size = sizes[sizes.len() / 2];
    let p95_idx = (sizes.len() as f64 * 0.95) as usize;
    let p95_size = sizes[p95_idx.min(sizes.len() - 1)];
    let total_bytes: u64 = sizes.iter().sum();

    WorkloadStats {
        median_size,
        p95_size,
        total_bytes,
    }
}

/// Adaptive routing decision: should this file be chunked by readers or sent directly to workers?
///
/// This is the core performance algorithm. The goal is to keep workers maximally busy.
///
/// Key principles:
/// - Chunking has overhead (reader threads, coordination)
/// - Chunking is only beneficial when we need to parallelize a file across multiple workers
/// - This happens when workers would otherwise be idle (few files remaining)
///
/// # Arguments
///
/// * `files_remaining` - How many files are left to process (including this one)
/// * `num_workers` - Number of worker threads available
/// * `file_size` - Size of this file in bytes
/// * `is_compressed` - Whether the file is compressed (affects routing due to decompression overhead)
/// * `stats` - Workload statistics (median, P95 file sizes)
///
/// # Returns
///
/// `true` if file should be chunked, `false` if it should go directly to workers
fn decide_routing(
    files_remaining: usize,
    num_workers: usize,
    file_size: u64,
    is_compressed: bool,
    stats: &WorkloadStats,
) -> bool {
    // Scenario 1: Many files remaining (> 2x workers)
    // Workers will stay continuously busy processing whole files
    // Chunking adds overhead with no benefit
    // Exception: Large compressed files benefit from parallel decompression in readers
    if files_remaining > num_workers * 2 {
        // Large compressed files (>200MB) benefit from reader decompression even with many files
        if is_compressed && file_size > 200 * 1024 * 1024 {
            return true;
        }
        return false; // Send direct to workers
    }

    // Scenario 2: Moderate files remaining (1-2x workers)
    // Workers mostly busy, only chunk massive outliers or large compressed files
    if files_remaining > num_workers {
        // Compressed files >100MB benefit from reader decompression
        if is_compressed && file_size > 100 * 1024 * 1024 {
            return true;
        }
        // Is this file a massive outlier (10x median AND > 500MB)?
        let is_huge_outlier =
            file_size > stats.median_size.saturating_mul(10) && file_size > 500 * 1024 * 1024;
        return is_huge_outlier;
    }

    // Scenario 3: Few files remaining (< num_workers, but > 3)
    // Some workers will be idle soon - chunk large files to parallelize
    if files_remaining > 3 {
        // Compressed files >50MB go through readers for decompression
        if is_compressed && file_size > 50 * 1024 * 1024 {
            return true;
        }
        // Chunk if significantly larger than typical files
        let is_large =
            file_size > stats.p95_size || file_size > stats.median_size.saturating_mul(5);
        let is_worth_chunking = file_size >= 100 * 1024 * 1024; // > 100MB
        return is_large && is_worth_chunking;
    }

    // Scenario 4: Last few files (1-3 remaining)
    // Most/all workers finishing up - aggressive chunking to avoid stragglers
    // Compressed files >50MB always go through readers for parallel decompression
    if is_compressed && file_size > 50 * 1024 * 1024 {
        return true;
    }
    // Chunk if EITHER:
    // - File is significantly larger than median (2x+) AND worth parallelizing (> 300MB)
    //   This catches stragglers like 600MB file after 15x 200MB files
    // - File is huge (> 1GB) AND median is small (< 1GB)
    //   This handles single-file scenarios or where most files are small
    //   but avoids chunking uniform huge-file workloads (1000x 5GB files)
    let is_straggler =
        file_size > stats.median_size.saturating_mul(2) && file_size > 300 * 1024 * 1024;
    let is_huge_with_small_median = file_size > 1024 * 1024 * 1024 // > 1GB
                                  && stats.median_size < 1024 * 1024 * 1024; // median < 1GB

    is_straggler || is_huge_with_small_median
}

/// Simulate routing algorithm to count how many files will be chunked
///
/// This allows us to spawn exactly the right number of reader threads (could be 0!)
/// instead of guessing upfront.
fn count_files_to_chunk(
    file_infos: &[FileInfo],
    workload_stats: &WorkloadStats,
    num_workers: usize,
) -> usize {
    let file_count = file_infos.len();
    let mut count = 0;

    for (idx, file_info) in file_infos.iter().enumerate() {
        if file_info.is_stdin {
            count += 1; // stdin always chunks (unknown size)
            continue;
        }

        let files_remaining = file_count - idx;

        // Use same routing logic to predict outcome
        if decide_routing(
            files_remaining,
            num_workers,
            file_info.size,
            file_info.is_compressed,
            workload_stats,
        ) {
            count += 1;
        }
    }

    count
}

/// Process multiple files in parallel using producer/reader/worker architecture
///
/// This function uses a three-tier parallelism model:
/// - **Main thread**: Analyzes files and routes them to appropriate queues
/// - **Reader threads**: Parallel I/O and chunking for large files  
/// - **Worker threads**: Pattern extraction and database matching
///
/// # Arguments
///
/// * `files` - List of file paths to process
/// * `num_readers` - Number of reader threads for file I/O (default: num_cpus / 2)
/// * `num_workers` - Number of worker threads for processing (default: num_cpus)
/// * `create_worker` - Factory function that creates a Worker for each worker thread
///
/// # Returns
///
/// Returns `ParallelProcessingResult` containing both matches and routing statistics
///
/// # Example
///
/// ```rust,no_run
/// use matchy::{Database, processing, extractor::Extractor};
/// use std::sync::Arc;
///
/// let files = vec!["access.log".into(), "errors.log".into()];
///
/// let result = processing::process_files_parallel(
///     files,
///     None, // Use default reader count
///     None, // Use default worker count  
///     || {
///         let extractor = Extractor::new()
///             .map_err(|e| format!("Extractor error: {}", e))?;
///         let db = Database::from("threats.mxy").open()
///             .map_err(|e| format!("Database error: {}", e))?;
///         
///         let worker = processing::Worker::builder()
///             .extractor(extractor)
///             .add_database("threats", Arc::new(db))
///             .build();
///         
///         Ok::<_, String>(worker)
///     },
///     None::<fn(&processing::WorkerStats)>, // No progress callback
///     false,
/// )?;
///
/// println!("Found {} matches across all files", result.matches.len());
/// println!("Routing: {} to workers, {} to readers",
///     result.routing_stats.files_to_workers,
///     result.routing_stats.files_to_readers);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn process_files_parallel<F, P>(
    files: Vec<PathBuf>,
    num_readers: Option<usize>,
    num_workers: Option<usize>,
    create_worker: F,
    progress_callback: Option<P>,
    debug_routing: bool,
) -> Result<ParallelProcessingResult, String>
where
    F: Fn() -> Result<Worker, String> + Sync + Send + 'static,
    P: Fn(&WorkerStats) + Sync + Send + 'static,
{
    let num_cpus = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let num_workers = num_workers.unwrap_or(num_cpus);

    // Phase 1: Collect file metadata and compute workload statistics upfront
    let file_infos = collect_file_metadata(&files)?;
    let workload_stats = compute_workload_stats(&file_infos);
    let file_count = file_infos.len();

    // Phase 2: Simulate routing to determine optimal reader count
    let files_to_chunk = count_files_to_chunk(&file_infos, &workload_stats, num_workers);

    // Debug output: show workload analysis
    if debug_routing {
        eprintln!("\n[DEBUG] === Routing Analysis ===");
        eprintln!("[DEBUG] Workload statistics:");
        eprintln!("[DEBUG]   Total files: {}", file_count);
        eprintln!(
            "[DEBUG]   Median size: {} bytes ({:.2} MB)",
            workload_stats.median_size,
            workload_stats.median_size as f64 / (1024.0 * 1024.0)
        );
        eprintln!(
            "[DEBUG]   P95 size: {} bytes ({:.2} MB)",
            workload_stats.p95_size,
            workload_stats.p95_size as f64 / (1024.0 * 1024.0)
        );
        eprintln!(
            "[DEBUG]   Total bytes: {} ({:.2} GB)",
            workload_stats.total_bytes,
            workload_stats.total_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
        );
        eprintln!("[DEBUG]   Workers: {}", num_workers);
        eprintln!("[DEBUG]   Predicted files to chunk: {}", files_to_chunk);
        eprintln!();
    }

    // Determine reader pool size based on actual chunking workload
    let num_readers = num_readers.unwrap_or_else(|| {
        if files_to_chunk == 0 {
            0 // No readers needed - all files go direct to workers!
        } else if files_to_chunk <= 3 {
            1 // Few files to chunk, single reader handles easily
        } else if files_to_chunk <= 10 {
            2 // Moderate chunking workload
        } else {
            // Heavy chunking: allocate more readers, but cap at 1/3 of workers
            (files_to_chunk / 10).max(2).min(num_workers / 3)
        }
    });

    // Two-queue architecture for dynamic work distribution:
    // 1. file_queue: Files that need chunking (readers pull from here)
    // 2. work_queue: Work units ready to process (workers pull from here)
    // Using crossbeam-channel for lock-free MPMC (receivers are clonable)
    let (file_sender, file_receiver) = unbounded::<PathBuf>();
    let (work_sender, work_receiver) = unbounded::<WorkUnit>();

    // Wrap factory and progress callback in Arc for sharing across threads
    let worker_factory = Arc::new(create_worker);
    let progress_callback = progress_callback.map(Arc::new);

    // Shared map of per-worker stats for aggregated progress reporting
    let worker_stats_map = Arc::new(Mutex::new(
        std::collections::HashMap::<usize, WorkerStats>::new(),
    ));

    // Create SystemState for dynamic routing decisions
    let system_state = Arc::new(SystemState::new(num_workers, num_readers));

    // Spawn reader pool ONLY if files will be chunked (could be 0 readers!)
    let mut reader_handles = Vec::new();
    if num_readers > 0 {
        for _reader_id in 0..num_readers {
            let file_rx = file_receiver.clone();
            let work_tx = work_sender.clone();
            let state = Arc::clone(&system_state);

            let handle = thread::spawn(move || {
                // Pull files from queue and chunk them
                // crossbeam-channel receivers are clonable, no mutex needed
                while let Ok(file_path) = file_rx.recv() {
                    state.dec_reader_queue(); // File removed from queue

                    // Chunk this file and send chunks to work queue
                    if let Err(e) = reader_thread_chunker(file_path, &work_tx) {
                        eprintln!("Reader error: {}", e);
                    }
                    state.record_chunk_processed();
                }
            });

            reader_handles.push(handle);
        }
    }

    // Spawn worker threads
    // Workers pull work units from work_queue and process them
    let mut worker_handles = Vec::new();
    for worker_id in 0..num_workers {
        let receiver = work_receiver.clone();
        let factory = Arc::clone(&worker_factory);
        let state = Arc::clone(&system_state);

        let progress_cb = progress_callback.clone();
        let stats_map = Arc::clone(&worker_stats_map);

        let handle = thread::spawn(move || -> (Vec<MatchResult>, WorkerStats) {
            // Create worker for this thread
            let mut worker = match factory() {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("Worker creation failed: {}", e);
                    return (Vec::new(), WorkerStats::default());
                }
            };

            let mut local_matches = Vec::new();
            let mut last_progress = std::time::Instant::now();
            let progress_interval = std::time::Duration::from_millis(100);

            // Process work units until channel closes
            // crossbeam-channel receivers are clonable, no mutex needed
            while let Ok(unit) = receiver.recv() {
                state.dec_worker_queue(); // Work unit removed from queue

                match process_work_unit_with_worker(&unit, &mut worker) {
                    Ok(matches) => {
                        local_matches.extend(matches);
                    }
                    Err(e) => {
                        eprintln!("Processing error: {}", e);
                    }
                }

                // Record completion for dynamic routing decisions
                if matches!(unit, WorkUnit::WholeFile { .. }) {
                    state.record_file_completion();
                }

                // Call progress callback periodically
                if let Some(ref cb) = progress_cb {
                    let now = std::time::Instant::now();
                    if now.duration_since(last_progress) >= progress_interval {
                        // Update this worker's stats in the shared map
                        stats_map
                            .lock()
                            .unwrap()
                            .insert(worker_id, worker.stats().clone());

                        // Aggregate all workers' stats and call progress callback
                        let aggregated = {
                            let map = stats_map.lock().unwrap();
                            let mut agg = WorkerStats::default();
                            for stats in map.values() {
                                agg.lines_processed += stats.lines_processed;
                                agg.candidates_tested += stats.candidates_tested;
                                agg.matches_found += stats.matches_found;
                                agg.total_bytes += stats.total_bytes;
                                agg.extraction_time += stats.extraction_time;
                                agg.extraction_samples += stats.extraction_samples;
                                agg.lookup_time += stats.lookup_time;
                                agg.lookup_samples += stats.lookup_samples;
                                agg.ipv4_count += stats.ipv4_count;
                                agg.ipv6_count += stats.ipv6_count;
                                agg.domain_count += stats.domain_count;
                                agg.email_count += stats.email_count;
                            }
                            agg
                        };

                        cb(&aggregated);
                        last_progress = now;
                    }
                }
            }

            // Return matches and stats from this worker
            let stats = worker.stats().clone();
            (local_matches, stats)
        });

        worker_handles.push(handle);
    }

    // Phase 3: Route files adaptively based on workload characteristics
    let mut routing_stats = RoutingStats::default();

    if debug_routing {
        eprintln!("[DEBUG] === Per-File Routing Decisions ===");
    }

    for (idx, file_info) in file_infos.iter().enumerate() {
        let files_remaining = file_count - idx;

        // Wait until we have capacity to route (dynamic routing - late binding!)
        while !system_state.has_routing_capacity() {
            thread::sleep(Duration::from_millis(10));
        }

        if file_info.is_stdin {
            // Always route stdin to file queue for chunking (can't stat it, unknown size)
            routing_stats.files_to_readers += 1;
            routing_stats.bytes_to_readers += 0; // Size unknown

            if debug_routing {
                eprintln!(
                    "[DEBUG] File {}: {} (stdin) → READER (unknown size, always chunk)",
                    idx,
                    file_info.path.display()
                );
            }

            system_state.inc_reader_queue(); // Track queue depth
            file_sender
                .send(file_info.path.clone())
                .map_err(|_| "File queue closed unexpectedly")?;
        } else {
            // Apply adaptive routing decision
            let should_chunk = decide_routing(
                files_remaining,
                num_workers,
                file_info.size,
                file_info.is_compressed,
                &workload_stats,
            );

            // Determine which scenario applied for debug output
            let scenario = if files_remaining > num_workers * 2 {
                "Scenario 1: many files"
            } else if files_remaining > num_workers {
                "Scenario 2: moderate files"
            } else if files_remaining > 3 {
                "Scenario 3: few files"
            } else {
                "Scenario 4: last few files (straggler detection)"
            };

            if should_chunk && num_readers > 0 {
                // Route to reader pool for chunking
                routing_stats.files_to_readers += 1;
                routing_stats.bytes_to_readers += file_info.size;

                if debug_routing {
                    let size_mb = file_info.size as f64 / (1024.0 * 1024.0);
                    let vs_median =
                        file_info.size as f64 / workload_stats.median_size.max(1) as f64;
                    eprintln!(
                        "[DEBUG] File {}: {} ({:.1} MB, {:.1}x median) → READER ({})",
                        idx,
                        file_info.path.display(),
                        size_mb,
                        vs_median,
                        scenario
                    );
                }

                system_state.inc_reader_queue(); // Track queue depth
                file_sender
                    .send(file_info.path.clone())
                    .map_err(|_| "File queue closed unexpectedly")?;
            } else {
                // Route directly to workers as whole file
                routing_stats.files_to_workers += 1;
                routing_stats.bytes_to_workers += file_info.size;

                if debug_routing {
                    let size_mb = file_info.size as f64 / (1024.0 * 1024.0);
                    let vs_median =
                        file_info.size as f64 / workload_stats.median_size.max(1) as f64;
                    eprintln!(
                        "[DEBUG] File {}: {} ({:.1} MB, {:.1}x median) → WORKER ({})",
                        idx,
                        file_info.path.display(),
                        size_mb,
                        vs_median,
                        scenario
                    );
                }

                system_state.inc_worker_queue(); // Track queue depth
                work_sender
                    .send(WorkUnit::WholeFile {
                        path: file_info.path.clone(),
                    })
                    .map_err(|_| "Work queue closed unexpectedly")?;
            }
        }
    }

    if debug_routing {
        eprintln!("\n[DEBUG] === Routing Summary ===");
        eprintln!("[DEBUG] Readers spawned: {}", num_readers);
        eprintln!(
            "[DEBUG] Files to workers: {}",
            routing_stats.files_to_workers
        );
        eprintln!(
            "[DEBUG] Files to readers: {}",
            routing_stats.files_to_readers
        );
        eprintln!();
    }

    // Close file queue - readers will finish their current files and exit
    drop(file_sender);

    // Wait for all reader threads to finish
    for handle in reader_handles {
        if let Err(e) = handle.join() {
            eprintln!("Reader thread panicked: {:?}", e);
        }
    }

    // Now that all readers are done, close work queue - workers will drain and exit
    drop(work_sender);

    // Wait for all worker threads to finish and collect results
    let mut all_matches = Vec::new();
    let mut aggregate_stats = WorkerStats::default();

    for handle in worker_handles {
        match handle.join() {
            Ok((matches, stats)) => {
                all_matches.extend(matches);
                // Aggregate stats
                aggregate_stats.lines_processed += stats.lines_processed;
                aggregate_stats.candidates_tested += stats.candidates_tested;
                aggregate_stats.matches_found += stats.matches_found;
                aggregate_stats.total_bytes += stats.total_bytes;
                aggregate_stats.extraction_time += stats.extraction_time;
                aggregate_stats.extraction_samples += stats.extraction_samples;
                aggregate_stats.lookup_time += stats.lookup_time;
                aggregate_stats.lookup_samples += stats.lookup_samples;
                aggregate_stats.ipv4_count += stats.ipv4_count;
                aggregate_stats.ipv6_count += stats.ipv6_count;
                aggregate_stats.domain_count += stats.domain_count;
                aggregate_stats.email_count += stats.email_count;
            }
            Err(e) => {
                eprintln!("Worker thread panicked: {:?}", e);
            }
        }
    }

    Ok(ParallelProcessingResult {
        matches: all_matches,
        routing_stats,
        worker_stats: aggregate_stats,
        actual_readers: num_readers,
        actual_workers: num_workers,
    })
}

/// Process a work unit using a Worker instance
fn process_work_unit_with_worker(
    unit: &WorkUnit,
    worker: &mut Worker,
) -> Result<Vec<MatchResult>, String> {
    match unit {
        WorkUnit::WholeFile { path } => {
            // Open and process entire file
            let mut reader = FileReader::new(path, 128 * 1024)
                .map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;

            let mut all_matches = Vec::new();

            while let Some(batch) = reader
                .next_batch()
                .map_err(|e| format!("Read error in {}: {}", path.display(), e))?
            {
                // Use Worker's process_batch method
                let matches = worker.process_batch(&batch)?;
                all_matches.extend(matches);
            }

            Ok(all_matches)
        }
        WorkUnit::Chunk { batch } => {
            // Process pre-chunked data directly using Worker
            worker.process_batch(batch)
        }
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
    fn test_chunk_size_selection() {
        // Uncompressed files: smaller chunks for parallelism
        assert_eq!(chunk_size_for(500 * 1024 * 1024, false), 256 * 1024);
        assert_eq!(chunk_size_for(5 * 1024 * 1024 * 1024, false), 1024 * 1024);
        assert_eq!(
            chunk_size_for(50 * 1024 * 1024 * 1024, false),
            4 * 1024 * 1024
        );

        // Compressed files: larger chunks to amortize decompression
        assert_eq!(chunk_size_for(500 * 1024 * 1024, true), 4 * 1024 * 1024);
        assert_eq!(
            chunk_size_for(5 * 1024 * 1024 * 1024, true),
            16 * 1024 * 1024
        );
        assert_eq!(
            chunk_size_for(50 * 1024 * 1024 * 1024, true),
            32 * 1024 * 1024
        );
    }

    #[test]
    fn test_routing_scenario_many_huge_files() {
        // Real-world scenario: 1000 huge compressed files
        // Expected: All files go direct to workers, 0 readers spawned
        let num_workers = 8;
        let stats = WorkloadStats {
            median_size: 5 * 1024 * 1024 * 1024,    // 5GB median
            p95_size: 8 * 1024 * 1024 * 1024,       // 8GB P95
            total_bytes: 5000 * 1024 * 1024 * 1024, // 5TB total
        };

        // First 950 files: plenty remaining, don't chunk
        for i in 0..950 {
            let files_remaining = 1000 - i;
            let should_chunk = decide_routing(
                files_remaining,
                num_workers,
                5 * 1024 * 1024 * 1024, // 5GB files
                false,                  // uncompressed
                &stats,
            );
            assert!(
                !should_chunk,
                "File {} (remaining={}) should NOT chunk with many files",
                i, files_remaining
            );
        }

        // Files 951-997: moderate remaining, still don't chunk normal-sized files
        for i in 950..997 {
            let files_remaining = 1000 - i;
            let should_chunk = decide_routing(
                files_remaining,
                num_workers,
                5 * 1024 * 1024 * 1024, // 5GB (not an outlier)
                false,                  // uncompressed
                &stats,
            );
            assert!(
                !should_chunk,
                "File {} (remaining={}) should NOT chunk (not an outlier)",
                i, files_remaining
            );
        }

        // Last 3 files: only chunk if > 2x median = 10GB
        for i in 997..1000 {
            let files_remaining = 1000 - i;
            let should_chunk_normal = decide_routing(
                files_remaining,
                num_workers,
                5 * 1024 * 1024 * 1024, // 5GB = 1x median
                false,                  // uncompressed
                &stats,
            );
            let should_chunk_large = decide_routing(
                files_remaining,
                num_workers,
                12 * 1024 * 1024 * 1024, // 12GB = 2.4x median
                false,                   // uncompressed
                &stats,
            );
            assert!(
                !should_chunk_normal,
                "File {} (remaining={}, 5GB) should NOT chunk (< 2x median)",
                i, files_remaining
            );
            assert!(
                should_chunk_large,
                "File {} (remaining={}, 12GB) SHOULD chunk (> 2x median)",
                i, files_remaining
            );
        }
    }

    #[test]
    fn test_routing_scenario_journal_logs_with_tarball() {
        // Real-world scenario from user:
        // 15 files @ 200MB each (uncompressed journal logs)
        // 1 file @ 600MB (compressed tarball)
        // Expected: First 15 direct to workers, last file (600MB) should chunk
        let num_workers = 8;
        let stats = WorkloadStats {
            median_size: 209715200,  // ~200MB
            p95_size: 209715200,     // ~200MB (uniform size)
            total_bytes: 3766210481, // ~3.5GB total
        };

        // Files 0-14: 200MB each, plenty remaining
        for i in 0..15 {
            let files_remaining = 16 - i;
            let should_chunk = decide_routing(
                files_remaining,
                num_workers,
                209715200, // 200MB
                false,     // uncompressed
                &stats,
            );
            assert!(
                !should_chunk,
                "File {} (remaining={}) should NOT chunk (many files)",
                i, files_remaining
            );
        }

        // File 15 (last): 600MB compressed tarball
        // files_remaining = 1
        // file_size (600MB) > median (200MB) * 2 ✓
        // Should chunk to avoid straggler!
        let should_chunk_tarball = decide_routing(
            1, // Last file
            num_workers,
            616354689, // ~600MB
            false,     // uncompressed
            &stats,
        );
        assert!(
            should_chunk_tarball,
            "Last file (600MB, 3x median) SHOULD chunk to avoid straggler"
        );
    }

    #[test]
    fn test_routing_scenario_five_large_files_with_outlier() {
        // Scenario: 5 large files, last one is massive outlier
        // Files 1-4: ~120MB
        // File 5: 1.3GB outlier
        let num_workers = 16;
        let stats = WorkloadStats {
            median_size: 120 * 1024 * 1024,  // 120MB
            p95_size: 130 * 1024 * 1024,     // 130MB
            total_bytes: 1800 * 1024 * 1024, // ~1.8GB total
        };

        // Files 0-3: normal size, few files remaining but not in straggler zone yet
        for i in 0..4 {
            let files_remaining = 5 - i;
            let should_chunk = decide_routing(
                files_remaining,
                num_workers,
                120 * 1024 * 1024, // 120MB
                false,             // uncompressed
                &stats,
            );
            // files_remaining = 5,4 (> 3) → use Scenario 3 rules
            // 120MB < P95 (130MB) and 120MB < 5x median (600MB)
            // Should NOT chunk
            assert!(
                !should_chunk,
                "File {} (remaining={}, 120MB) should NOT chunk",
                i, files_remaining
            );
        }

        // File 4 (last): 1.3GB outlier
        // files_remaining = 1
        // 1.3GB > 2x median (240MB) ✓ AND > 300MB ✓
        // Should chunk!
        let should_chunk_outlier = decide_routing(
            1,
            num_workers,
            1346 * 1024 * 1024, // 1.3GB
            false,              // uncompressed
            &stats,
        );
        assert!(
            should_chunk_outlier,
            "Last file (1.3GB outlier) SHOULD chunk (> 2x median)"
        );
    }

    #[test]
    fn test_routing_scenario_single_massive_file() {
        // Scenario: Single 100GB file where median = file size
        // Current limitation: algorithm doesn't chunk uniform single-file workloads
        // This is acceptable because:
        // 1. Single file workloads are rare in practice
        // 2. User can use --readers=1 to force chunking if needed
        // 3. The file still gets processed (just not parallelized)
        let num_workers = 16;
        let stats = WorkloadStats {
            median_size: 100 * 1024 * 1024 * 1024, // 100GB (only file)
            p95_size: 100 * 1024 * 1024 * 1024,
            total_bytes: 100 * 1024 * 1024 * 1024,
        };

        let should_chunk = decide_routing(
            1,
            num_workers,
            100 * 1024 * 1024 * 1024, // 100GB
            false,                    // uncompressed
            &stats,
        );

        // Current behavior: does NOT chunk (median = file size, not larger)
        // This is acceptable - user can override with --readers if needed
        assert!(
            !should_chunk,
            "Single file where median=size doesn't chunk (use --readers to override)"
        );
    }

    #[test]
    fn test_routing_scenario_many_small_files() {
        // Scenario: 10000 small files (1MB each)
        // Expected: All direct to workers, never chunk
        let num_workers = 16;
        let stats = WorkloadStats {
            median_size: 1024 * 1024,         // 1MB
            p95_size: 1024 * 1024,            // 1MB
            total_bytes: 10000 * 1024 * 1024, // 10GB total
        };

        // All files: many remaining, small size
        for i in 0..10000 {
            let files_remaining = 10000 - i;
            let should_chunk = decide_routing(
                files_remaining,
                num_workers,
                1024 * 1024, // 1MB
                false,       // uncompressed
                &stats,
            );
            assert!(
                !should_chunk,
                "File {} should NOT chunk (many small files)",
                i
            );
        }
    }

    #[test]
    fn test_routing_scenario_moderate_outlier_in_middle() {
        // Scenario: 50 files @ 100MB, one 5GB outlier at position 25
        // Expected: First 33+ files direct, outlier chunks (if in moderate zone)
        let num_workers = 8;
        let stats = WorkloadStats {
            median_size: 100 * 1024 * 1024, // 100MB
            p95_size: 100 * 1024 * 1024,
            total_bytes: 5000 * 1024 * 1024, // ~5GB total
        };

        // File 0-32: many remaining (50-18 = 32 > 2*8 = 16)
        for i in 0..33 {
            let files_remaining = 50 - i;
            let should_chunk = decide_routing(
                files_remaining,
                num_workers,
                100 * 1024 * 1024, // 100MB
                false,             // uncompressed
                &stats,
            );
            assert!(
                !should_chunk,
                "File {} (remaining={}) should NOT chunk (many remaining)",
                i, files_remaining
            );
        }

        // File 25: 5GB outlier, files_remaining = 25
        // 25 > 2*num_workers (16) → Scenario 1 (many files)
        // Scenario 1: always send direct to workers (no chunking)
        // Even though it's a massive outlier, there are still many files remaining
        let should_chunk_outlier = decide_routing(
            25,
            num_workers,
            5 * 1024 * 1024 * 1024, // 5GB
            false,                  // uncompressed
            &stats,
        );
        assert!(
            !should_chunk_outlier,
            "Outlier with many files remaining (25 > 16) should NOT chunk (Scenario 1)"
        );
    }

    #[test]
    fn test_routing_count_files_to_chunk() {
        // Test the simulation function
        let num_workers = 8;

        // Scenario: 50 uniform files + 1 outlier at end
        let mut file_infos = Vec::new();
        for _ in 0..50 {
            file_infos.push(FileInfo {
                path: PathBuf::from("file.log"),
                size: 200 * 1024 * 1024, // 200MB
                is_stdin: false,
                is_compressed: false,
            });
        }
        file_infos.push(FileInfo {
            path: PathBuf::from("huge.tar.gz"),
            size: 2 * 1024 * 1024 * 1024, // 2GB outlier
            is_stdin: false,
            is_compressed: true, // .tar.gz is compressed
        });

        let workload_stats = compute_workload_stats(&file_infos);
        let files_to_chunk = count_files_to_chunk(&file_infos, &workload_stats, num_workers);

        // Should chunk only the last file (outlier)
        assert_eq!(
            files_to_chunk, 1,
            "Should chunk exactly 1 file (the outlier)"
        );
    }
}
