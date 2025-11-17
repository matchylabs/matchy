use anyhow::{Context, Result};
use serde_json::json;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::stats::ProcessingStats;
use crate::cli_utils::{data_value_to_json, format_cidr_into};

/// Extractor configuration from CLI flags
#[derive(Debug, Clone, Default)]
pub struct ExtractorConfig {
    pub overrides: HashMap<String, bool>,
    /// True if any explicit enables were specified (positive values)
    /// When true, defaults are disabled (exclusive mode)
    has_enables: bool,
}

impl ExtractorConfig {
    pub fn from_arg(arg: Option<String>) -> Self {
        let mut overrides = HashMap::new();
        let mut has_enables = false;

        if let Some(ref extractors_str) = arg {
            for extractor in extractors_str.split(',') {
                let extractor = extractor.trim();
                let (is_disable, name) = if let Some(name) = extractor.strip_prefix('-') {
                    (true, name)
                } else {
                    (false, extractor)
                };

                // Track if any explicit enables (positive values)
                if !is_disable {
                    has_enables = true;
                }

                // Expand group aliases
                let names = Self::expand_alias(name);

                for n in names {
                    overrides.insert(n.to_string(), !is_disable);
                }
            }
        }

        Self {
            overrides,
            has_enables,
        }
    }

    /// Expand group aliases and normalize names
    fn expand_alias(name: &str) -> Vec<&str> {
        match name {
            // Group aliases
            "crypto" => vec!["bitcoin", "ethereum", "monero"],
            "ip" => vec!["ipv4", "ipv6"],
            // Plural normalization
            "domains" => vec!["domain"],
            "emails" => vec!["email"],
            "hashes" => vec!["hash"],
            "ips" => vec!["ipv4", "ipv6"],
            // Pass through as-is
            _ => vec![name],
        }
    }

    pub fn should_enable(&self, name: &str, default: bool) -> bool {
        self.overrides.get(name).copied().unwrap_or(default)
    }

    /// Returns true if any explicit enables were specified
    /// Used to determine if we're in exclusive mode (only enable what was specified)
    pub fn has_explicit_enables(&self) -> bool {
        self.has_enables
    }
}

// Use library's LineBatch directly instead of maintaining duplicate WorkBatch
pub use matchy::processing::LineBatch;

/// Auto-tune thread count based on workload characteristics
/// Optimized for large-scale workloads (thousands of files, multi-TB datasets)
/// Returns (num_readers, num_workers)
fn auto_tune_thread_count(inputs: &[PathBuf], show_stats: bool) -> (usize, usize) {
    // Get available parallelism (physical cores or CPU quota)
    let physical_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .max(1);

    // Count regular files (exclude stdin)
    let file_count = inputs.iter().filter(|p| p.to_str() != Some("-")).count();

    // Count compressed files
    let compressed_count = inputs
        .iter()
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("gz") || e.eq_ignore_ascii_case("bz2"))
                .unwrap_or(false)
        })
        .count();

    // Strategy for large-scale workloads:
    // - Many files: workers process whole files directly (minimal reader overhead)
    // - Few files: readers chunk large files to keep workers busy
    // - Runtime routing handles mixed file sizes dynamically

    let (num_readers, num_workers) = if file_count > physical_cores * 2 {
        // Many files scenario (common for large-scale workloads)
        // Small files go directly to workers, only large files get chunked
        // Minimal readers (1-2), maximize workers
        let readers = if compressed_count > 0 { 2 } else { 1 };
        let workers = physical_cores.saturating_sub(readers).max(1);
        (readers, workers)
    } else if file_count <= 1 {
        // Single file: must chunk to keep workers busy
        (1, physical_cores.saturating_sub(1).max(1))
    } else {
        // Few files (2 to 2*cores): chunk them to maximize parallelism
        // For compressed files, workers handle decompression (CPU-intensive)
        // so still prioritize workers over readers
        let readers = if compressed_count > file_count / 2 {
            2 // Compressed: 2 readers, rest workers
        } else {
            (physical_cores / 4).max(1).min(3) // Uncompressed: ~25% readers, capped at 3
        };
        let workers = physical_cores.saturating_sub(readers).max(1);
        (readers, workers)
    };

    if show_stats {
        eprintln!(
            "[INFO] Auto-tuning: {} physical cores detected",
            physical_cores
        );
        eprintln!(
            "[INFO] Workload: {} files ({} compressed)",
            file_count, compressed_count
        );
        eprintln!(
            "[INFO] Configuration: {} reader(s), {} worker(s)",
            num_readers, num_workers
        );

        if file_count > physical_cores * 2 {
            eprintln!("[INFO] Strategy: Large-scale workload - workers process files directly");
        } else if file_count <= 1 {
            eprintln!("[INFO] Strategy: Single file - chunk to maximize parallelism");
        } else {
            eprintln!("[INFO] Strategy: Few files - chunk large files to keep workers busy");
        }
    }

    (num_readers, num_workers)
}

/// Match result sent from workers to output thread
pub struct MatchResult {
    pub source_file: PathBuf,
    pub line_number: usize,
    pub matched_text: String,
    pub match_type: String,
    pub input_line: String,
    pub timestamp: f64,
    // Optional fields for different match types
    pub pattern_count: Option<usize>,
    pub data: Option<serde_json::Value>,
    pub prefix_len: Option<u8>,
    pub cidr: Option<String>,
}

// Use library's WorkerStats directly instead of maintaining a duplicate type
pub use matchy::processing::WorkerStats;
/// Process multiple files in parallel using library's producer/reader/worker architecture
///
/// If num_threads is 0 (auto), determines optimal thread count based on:
/// - Physical CPU cores
/// - Number of input files
/// - File types (compressed vs uncompressed)
#[allow(clippy::too_many_arguments)]
pub fn process_parallel(
    inputs: Vec<PathBuf>,
    database_path: &Path,
    num_threads: usize,
    explicit_readers: Option<usize>,
    _batch_bytes: usize,
    output_format: &str,
    show_stats: bool,
    _show_progress: bool,
    cache_size: usize,
    _overall_start: Instant,
    extractor_config: ExtractorConfig,
) -> Result<(
    ProcessingStats,
    usize,
    usize,
    matchy::processing::RoutingStats,
)> {
    // Determine reader and worker counts
    let (num_readers, num_workers) = if let Some(readers) = explicit_readers {
        // Explicit reader count specified
        let workers = if num_threads == 0 {
            // Auto-detect total cores, subtract readers
            let physical_cores = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
                .max(1);
            physical_cores.saturating_sub(readers).max(1)
        } else {
            num_threads
        };
        (readers, workers)
    } else if num_threads == 0 {
        // Full auto-tune
        auto_tune_thread_count(&inputs, show_stats)
    } else {
        // Explicit thread count only - use simplified auto-tune for readers
        let file_count = inputs.iter().filter(|p| p.to_str() != Some("-")).count();

        // Apply same strategy as full auto-tune, but with explicit total thread count
        let readers = if file_count > num_threads * 2 {
            // Many files: minimal readers
            1
        } else if file_count <= 1 {
            // Single file: 1 reader
            1
        } else {
            // Few files: allocate ~25% to readers, capped at 3
            (num_threads / 4).max(1).min(3)
        };
        let workers = num_threads.saturating_sub(readers).max(1);

        if show_stats {
            eprintln!(
                "[INFO] Configuration: {} reader(s), {} worker(s)",
                readers, workers
            );
        }

        (readers, workers)
    };

    let output_json = output_format == "json";

    // Setup progress reporting if requested
    let progress_reporter = if _show_progress {
        Some(Arc::new(Mutex::new(
            crate::match_processor::ProgressReporter::new(),
        )))
    } else {
        None
    };
    let overall_start = _overall_start;

    // Call library's process_files_parallel with worker factory
    let db_path = database_path.to_owned();
    let ext_config = extractor_config.clone();

    let result = matchy::processing::process_files_parallel(
        inputs,
        Some(num_readers),
        Some(num_workers),
        move || {
            // Create database
            let db = init_worker_database(&db_path, cache_size)
                .map_err(|e| format!("Database init failed: {}", e))?;

            // Create extractor
            let extractor = create_extractor_for_db(&db, &ext_config)
                .map_err(|e| format!("Extractor init failed: {}", e))?;

            // Create worker
            let worker = matchy::processing::Worker::builder()
                .extractor(extractor)
                .add_database("default", db)
                .build();

            Ok::<_, String>(worker)
        },
        progress_reporter.map(|pr| {
            move |stats: &matchy::processing::WorkerStats| {
                let mut reporter = pr.lock().unwrap();
                if reporter.should_update() {
                    // Convert WorkerStats to CLI ProcessingStats for display
                    let mut ps = ProcessingStats::new();
                    ps.lines_processed = stats.lines_processed;
                    ps.candidates_tested = stats.candidates_tested;
                    ps.total_matches = stats.matches_found;
                    ps.total_bytes = stats.total_bytes;
                    reporter.show(&ps, overall_start.elapsed());
                }
            }
        }),
    )
    .map_err(|e| anyhow::anyhow!("Parallel processing failed: {}", e))?;

    // Print newline after progress if it was shown
    if _show_progress {
        eprintln!();
    }

    // Output matches in CLI format
    for lib_match in &result.matches {
        if let Some(cli_match) = library_match_to_cli_match(lib_match) {
            output_cli_match(&cli_match, output_json)?;
        }
    }

    // Convert library WorkerStats to CLI ProcessingStats
    let mut aggregate = ProcessingStats::new();
    aggregate.lines_processed = result.worker_stats.lines_processed;
    aggregate.candidates_tested = result.worker_stats.candidates_tested;
    aggregate.total_matches = result.worker_stats.matches_found;
    aggregate.lines_with_matches = result.worker_stats.lines_with_matches;
    aggregate.total_bytes = result.worker_stats.total_bytes;
    aggregate.extraction_time = result.worker_stats.extraction_time;
    aggregate.extraction_samples = result.worker_stats.extraction_samples;
    aggregate.lookup_time = result.worker_stats.lookup_time;
    aggregate.lookup_samples = result.worker_stats.lookup_samples;
    aggregate.ipv4_count = result.worker_stats.ipv4_count;
    aggregate.ipv6_count = result.worker_stats.ipv6_count;
    aggregate.domain_count = result.worker_stats.domain_count;
    aggregate.email_count = result.worker_stats.email_count;

    Ok((aggregate, num_workers, num_readers, result.routing_stats))
}

/// Message from worker to output thread
pub enum WorkerMessage {
    Match(MatchResult),
    Stats {
        worker_id: usize,
        stats: WorkerStats,
    },
}

/// Initialize database for a worker thread
/// Initialize database for a worker thread
pub fn init_worker_database(database_path: &Path, cache_size: usize) -> Result<matchy::Database> {
    use matchy::Database;

    let mut opener = Database::from(database_path.to_str().unwrap());
    if cache_size == 0 {
        opener = opener.no_cache();
    } else {
        opener = opener.cache_capacity(cache_size);
    }
    opener.open().context("Failed to open database")
}

/// Create extractor configured for database capabilities and CLI overrides
pub fn create_extractor_for_db(
    db: &matchy::Database,
    config: &ExtractorConfig,
) -> Result<matchy::extractor::Extractor> {
    use matchy::extractor::Extractor;

    let has_ip = db.has_ip_data();
    let has_strings = db.has_literal_data() || db.has_glob_data();

    // Determine defaults based on whether user specified explicit includes
    // If user says --extractors=ip,domain (positive), ONLY enable those (exclusive mode)
    // If user says --extractors=-crypto (negative), enable all defaults except those
    let use_defaults = !config.has_explicit_enables();

    let default_ipv4 = use_defaults && has_ip;
    let default_ipv6 = use_defaults && has_ip;
    let default_domains = use_defaults && has_strings;
    let default_emails = use_defaults && has_strings;
    let default_hashes = use_defaults && has_strings;
    let default_bitcoin = use_defaults && has_strings;
    let default_ethereum = use_defaults && has_strings;
    let default_monero = use_defaults && has_strings;

    // Build extractor with CLI overrides
    Extractor::builder()
        .extract_ipv4(config.should_enable("ipv4", default_ipv4))
        .extract_ipv6(config.should_enable("ipv6", default_ipv6))
        .extract_domains(config.should_enable("domain", default_domains))
        .extract_emails(config.should_enable("email", default_emails))
        .extract_hashes(config.should_enable("hash", default_hashes))
        .extract_bitcoin(config.should_enable("bitcoin", default_bitcoin))
        .extract_ethereum(config.should_enable("ethereum", default_ethereum))
        .extract_monero(config.should_enable("monero", default_monero))
        .build()
        .context("Failed to create extractor")
}

/// Reusable buffers for match result construction (eliminates per-match allocations)
pub struct MatchBuffers {
    data_values: Vec<serde_json::Value>,
    matched_text: String,
    cidr: String,
}

impl MatchBuffers {
    pub fn new() -> Self {
        Self {
            data_values: Vec::with_capacity(8),
            matched_text: String::with_capacity(256),
            cidr: String::with_capacity(64),
        }
    }
}

/// Convert library LineMatch to CLI MatchResult
fn library_match_to_cli_match(lib_match: &matchy::processing::LineMatch) -> Option<MatchResult> {
    use matchy::QueryResult;

    let mr = &lib_match.match_result;

    match &mr.result {
        QueryResult::Ip { data, prefix_len } => {
            let mut cidr = String::new();
            format_cidr_into(&mr.matched_text, *prefix_len, &mut cidr);

            Some(MatchResult {
                source_file: lib_match.source.clone(),
                line_number: lib_match.line_number,
                matched_text: mr.matched_text.clone(),
                match_type: "ip".to_string(),
                input_line: lib_match.input_line.clone(),
                timestamp: 0.0,
                pattern_count: None,
                data: Some(data_value_to_json(data)),
                prefix_len: Some(*prefix_len),
                cidr: Some(cidr),
            })
        }
        QueryResult::Pattern { pattern_ids, data } => {
            let data_values: Vec<_> = data
                .iter()
                .filter_map(|opt_dv| opt_dv.as_ref().map(data_value_to_json))
                .collect();

            Some(MatchResult {
                source_file: lib_match.source.clone(),
                line_number: lib_match.line_number,
                matched_text: mr.matched_text.clone(),
                match_type: "pattern".to_string(),
                input_line: lib_match.input_line.clone(),
                timestamp: 0.0,
                pattern_count: Some(pattern_ids.len()),
                data: if data_values.is_empty() {
                    None
                } else {
                    Some(serde_json::Value::Array(data_values))
                },
                prefix_len: None,
                cidr: None,
            })
        }
        QueryResult::NotFound => None,
    }
}

/// Output a CLI match result
fn output_cli_match(result: &MatchResult, output_json: bool) -> Result<()> {
    if output_json {
        let mut match_obj = json!({
            "timestamp": format!("{:.3}", result.timestamp),
            "source_file": result.source_file.display().to_string(),
            "line_number": result.line_number,
            "matched_text": result.matched_text,
            "input_line": result.input_line,
            "match_type": result.match_type,
        });

        if let Some(pattern_count) = result.pattern_count {
            match_obj["pattern_count"] = json!(pattern_count);
        }
        if let Some(ref data) = result.data {
            match_obj["data"] = data.clone();
        }
        if let Some(prefix_len) = result.prefix_len {
            match_obj["prefix_len"] = json!(prefix_len);
        }
        if let Some(ref cidr) = result.cidr {
            match_obj["cidr"] = json!(cidr);
        }

        println!("{}", serde_json::to_string(&match_obj)?);
    }
    Ok(())
}

/// Build CLI match result from library match
pub fn build_match_result(
    lib_match: &matchy::processing::LineMatch,
    match_buffers: &mut MatchBuffers,
) -> Option<MatchResult> {
    use matchy::QueryResult;

    // Reset buffers
    match_buffers.data_values.clear();
    match_buffers.matched_text.clear();
    match_buffers.cidr.clear();

    // Access the nested match_result
    let mr = &lib_match.match_result;

    // Build match result based on query result type
    match &mr.result {
        QueryResult::Ip { data, prefix_len } => {
            format_cidr_into(&mr.matched_text, *prefix_len, &mut match_buffers.cidr);

            Some(MatchResult {
                source_file: lib_match.source.clone(),
                line_number: lib_match.line_number,
                matched_text: mr.matched_text.clone(),
                match_type: "ip".to_string(),
                input_line: lib_match.input_line.clone(),
                timestamp: 0.0, // Will be filled by caller
                pattern_count: None,
                data: Some(data_value_to_json(data)),
                prefix_len: Some(*prefix_len),
                cidr: Some(match_buffers.cidr.clone()),
            })
        }
        QueryResult::Pattern { pattern_ids, data } => {
            let data_values: Vec<_> = data
                .iter()
                .filter_map(|opt_dv| opt_dv.as_ref().map(data_value_to_json))
                .collect();

            Some(MatchResult {
                source_file: lib_match.source.clone(),
                line_number: lib_match.line_number,
                matched_text: mr.matched_text.clone(),
                match_type: "pattern".to_string(),
                input_line: lib_match.input_line.clone(),
                timestamp: 0.0,
                pattern_count: Some(pattern_ids.len()),
                data: if data_values.is_empty() {
                    None
                } else {
                    Some(serde_json::Value::Array(data_values))
                },
                prefix_len: None,
                cidr: None,
            })
        }
        QueryResult::NotFound => None,
    }
}
