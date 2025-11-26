use anyhow::{Context, Result};
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
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

// Use library's DataBatch directly instead of maintaining duplicate WorkBatch
pub use matchy::processing::DataBatch;

/// Auto-tune worker count based on available CPU cores
/// Reader count is determined dynamically by the library based on workload simulation
fn auto_tune_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .max(1)
}

/// Match result sent from workers to output thread
pub struct CliMatchResult {
    pub source_file: PathBuf,
    pub matched_text: String,
    pub match_type: String,
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
    db: Arc<matchy::Database>,
    num_threads: usize,
    explicit_readers: Option<usize>,
    _batch_bytes: usize,
    output_format: &str,
    _show_stats: bool,
    _show_progress: bool,
    _overall_start: Instant,
    extractor_config: ExtractorConfig,
    debug_routing: bool,
) -> Result<(
    ProcessingStats,
    usize,
    usize,
    matchy::processing::RoutingStats,
)> {
    // Determine worker count (readers determined dynamically by library)
    let num_workers = if num_threads == 0 {
        auto_tune_worker_count()
    } else {
        num_threads
    };

    // Reader count handling:
    // - If --readers specified explicitly: pass it through to library
    // - Otherwise: pass None, library will simulate routing and spawn exact number needed
    let num_readers_opt = explicit_readers;

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

    let ext_config = extractor_config.clone();

    let result = matchy::processing::process_files_parallel(
        inputs,
        num_readers_opt, // Library will simulate routing if None
        Some(num_workers),
        move || {
            // Clone the Arc (cheap - just increments refcount)
            let db_clone = Arc::clone(&db);

            // Create extractor
            let extractor = create_extractor_for_db(&db_clone, &ext_config)
                .map_err(|e| format!("Extractor init failed: {}", e))?;

            // Create worker with shared database
            let worker = matchy::processing::Worker::builder()
                .extractor(extractor)
                .add_database("default", db_clone)
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
        debug_routing, // Pass debug flag to library
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
    aggregate.total_bytes = result.worker_stats.total_bytes;
    aggregate.extraction_time = result.worker_stats.extraction_time;
    aggregate.extraction_samples = result.worker_stats.extraction_samples;
    aggregate.lookup_time = result.worker_stats.lookup_time;
    aggregate.lookup_samples = result.worker_stats.lookup_samples;
    aggregate.ipv4_count = result.worker_stats.ipv4_count;
    aggregate.ipv6_count = result.worker_stats.ipv6_count;
    aggregate.domain_count = result.worker_stats.domain_count;
    aggregate.email_count = result.worker_stats.email_count;

    Ok((
        aggregate,
        result.actual_workers,
        result.actual_readers,
        result.routing_stats,
    ))
}

/// Message from worker to output thread
pub enum WorkerMessage {
    Match(CliMatchResult),
    Stats {
        worker_id: usize,
        stats: WorkerStats,
    },
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

/// Convert library MatchResult to CLI CliMatchResult
fn library_match_to_cli_match(
    lib_match: &matchy::processing::MatchResult,
) -> Option<CliMatchResult> {
    use matchy::QueryResult;

    match &lib_match.result {
        QueryResult::Ip { data, prefix_len } => {
            let mut cidr = String::new();
            format_cidr_into(&lib_match.matched_text, *prefix_len, &mut cidr);

            Some(CliMatchResult {
                source_file: lib_match.source.clone(),
                matched_text: lib_match.matched_text.clone(),
                match_type: "ip".to_string(),
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

            Some(CliMatchResult {
                source_file: lib_match.source.clone(),
                matched_text: lib_match.matched_text.clone(),
                match_type: "pattern".to_string(),
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
fn output_cli_match(result: &CliMatchResult, output_json: bool) -> Result<()> {
    if output_json {
        let mut match_obj = json!({
            "timestamp": format!("{:.3}", result.timestamp),
            "source": result.source_file.display().to_string(),
            "matched_text": result.matched_text,
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
    lib_match: &matchy::processing::MatchResult,
    match_buffers: &mut MatchBuffers,
) -> Option<CliMatchResult> {
    use matchy::QueryResult;

    // Reset buffers
    match_buffers.data_values.clear();
    match_buffers.matched_text.clear();
    match_buffers.cidr.clear();

    // Build match result based on query result type
    match &lib_match.result {
        QueryResult::Ip { data, prefix_len } => {
            format_cidr_into(
                &lib_match.matched_text,
                *prefix_len,
                &mut match_buffers.cidr,
            );

            Some(CliMatchResult {
                source_file: lib_match.source.clone(),
                matched_text: lib_match.matched_text.clone(),
                match_type: "ip".to_string(),
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

            Some(CliMatchResult {
                source_file: lib_match.source.clone(),
                matched_text: lib_match.matched_text.clone(),
                match_type: "pattern".to_string(),
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
