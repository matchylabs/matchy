use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;

use crate::cli_utils::{format_number, format_qps, json_to_data_map};
use crate::match_processor::{
    analyze_performance, follow_files, follow_files_parallel, process_file_with_aggregate,
    process_parallel, ProcessingStats,
};
use matchy::{DataValue, DatabaseBuilder, MatchMode};

/// Check if the given path is a source file (JSON or CSV) that needs to be built
fn is_source_file(path: &Path) -> Option<&'static str> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .and_then(|ext| {
            let ext_lower = ext.to_lowercase();
            match ext_lower.as_str() {
                "json" => Some("json"),
                "csv" => Some("csv"),
                _ => None,
            }
        })
}

/// Build a database in-memory from a source file (JSON or CSV)
fn build_database_from_source(path: &Path, format: &str, show_stats: bool) -> Result<Vec<u8>> {
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    match format {
        "csv" => {
            // Read entries with data from CSV file
            let file = fs::File::open(path)
                .with_context(|| format!("Failed to open CSV file: {}", path.display()))?;
            let mut reader = csv::Reader::from_reader(file);

            // Get headers
            let headers = reader.headers().context("Failed to read CSV headers")?;

            // Find the entry column (try "entry" or "key")
            let entry_col = headers
                .iter()
                .position(|h| h == "entry" || h == "key")
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "CSV must have an 'entry' or 'key' column. Found headers: {}",
                        headers.iter().collect::<Vec<_>>().join(", ")
                    )
                })?;

            // Get other column names for metadata
            let data_cols: Vec<(usize, String)> = headers
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != entry_col)
                .map(|(i, name)| (i, name.to_string()))
                .collect();

            let mut total_entries = 0;

            // Process each row
            for (row_num, result) in reader.records().enumerate() {
                let record = result.context("Failed to read CSV record")?;

                // Get the entry value
                let entry = record.get(entry_col).ok_or_else(|| {
                    anyhow::anyhow!("Missing entry column at row {}", row_num + 2)
                })?;

                // Build data map from other columns
                let mut data = HashMap::new();
                for (col_idx, col_name) in &data_cols {
                    if let Some(value) = record.get(*col_idx) {
                        if !value.is_empty() {
                            // Try to parse as number, otherwise treat as string
                            let data_value = if let Ok(i) = value.parse::<i64>() {
                                DataValue::Int32(i as i32)
                            } else if let Ok(u) = value.parse::<u64>() {
                                DataValue::Uint64(u)
                            } else if let Ok(f) = value.parse::<f64>() {
                                DataValue::Double(f)
                            } else if value == "true" || value == "false" {
                                DataValue::Bool(value == "true")
                            } else {
                                DataValue::String(value.to_string())
                            };
                            data.insert(col_name.clone(), data_value);
                        }
                    }
                }

                builder.add_entry(entry, data)?;
                total_entries += 1;
            }

            if show_stats {
                eprintln!("[INFO] Loaded {} entries from CSV", total_entries);
            }
        }
        "json" => {
            // Read entries with data from JSON file
            let content = fs::read_to_string(path)
                .with_context(|| format!("Failed to read JSON file: {}", path.display()))?;
            let entries: Vec<serde_json::Value> =
                serde_json::from_str(&content).context("Failed to parse JSON")?;

            let mut total_entries = 0;

            for (i, item) in entries.iter().enumerate() {
                let key = item
                    .get("key")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing 'key' field at index {}", i))?;

                let data = if let Some(data_json) = item.get("data") {
                    json_to_data_map(data_json)?
                } else {
                    HashMap::new()
                };

                builder.add_entry(key, data)?;
                total_entries += 1;
            }

            if show_stats {
                eprintln!("[INFO] Loaded {} entries from JSON", total_entries);
            }
        }
        "text" => {
            // Read entries from text file (one per line)
            let file = fs::File::open(path)
                .with_context(|| format!("Failed to open input file: {}", path.display()))?;
            let reader = io::BufReader::new(file);

            let mut total_entries = 0;
            for line in reader.lines() {
                let line = line?;
                let entry = line.trim();
                if !entry.is_empty() && !entry.starts_with('#') {
                    builder.add_entry(entry, HashMap::new())?;
                    total_entries += 1;
                }
            }

            if show_stats {
                eprintln!("[INFO] Loaded {} entries from text file", total_entries);
            }
        }
        _ => {
            anyhow::bail!("Unknown format: {}. Use 'json', 'csv', or 'text'", format);
        }
    }

    // Show stats about what was loaded
    if show_stats {
        let stats = builder.stats();
        eprintln!(
            "[INFO] Database: {} IPs, {} literals, {} globs",
            stats.ip_entries, stats.literal_entries, stats.glob_entries
        );
    }

    builder.build().context("Failed to build database")
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_match(
    database: PathBuf,
    inputs: Vec<PathBuf>,
    follow: bool,
    threads_arg: Option<String>,
    readers_arg: Option<usize>,
    batch_bytes: usize,
    format: String,
    show_stats: bool,
    show_progress: bool,
    cache_size: usize,
    extractors_arg: Option<String>,
    debug_routing: bool,
) -> Result<()> {
    use matchy::extractor::Extractor;
    use matchy::Database;

    // Parse thread count: None = auto (0 triggers auto-tuning), "N" = N
    let num_threads = match threads_arg.as_deref() {
        None | Some("auto") | Some("0") => 0, // 0 = auto-tune in process_parallel
        Some(s) => s.parse::<usize>().with_context(|| {
            format!("Invalid thread count '{}', expected a number or 'auto'", s)
        })?,
    };

    if show_stats && !follow {
        if num_threads == 0 {
            eprintln!("[INFO] Mode: Auto-tuning (detecting optimal configuration)");
        } else if num_threads == 1 {
            eprintln!("[INFO] Mode: Sequential (single-threaded)");
        } else {
            // Show reader/worker split
            if let Some(readers) = readers_arg {
                eprintln!(
                    "[INFO] Mode: Parallel ({} readers, {} workers)",
                    readers, num_threads
                );
            } else {
                eprintln!("[INFO] Mode: Parallel (1 reader, {} workers)", num_threads);
            }
            eprintln!("[INFO] Batch size: {} bytes", batch_bytes);
        }
    }

    // Load database - either from compiled .mxy file or build from source (JSON/CSV)
    let load_start = Instant::now();
    let is_from_source = is_source_file(&database);

    let db = if let Some(source_format) = is_from_source {
        // Build database in-memory from source file
        if show_stats {
            eprintln!(
                "[INFO] Building database from {} file...",
                source_format.to_uppercase()
            );
        }
        let db_bytes = build_database_from_source(&database, source_format, show_stats)?;
        let mut opener = Database::from_bytes_builder(db_bytes);
        if cache_size == 0 {
            opener = opener.no_cache();
        } else {
            opener = opener.cache_capacity(cache_size);
        }
        opener
            .open()
            .with_context(|| format!("Failed to build database from: {}", database.display()))?
    } else {
        // Load from compiled database file
        let mut opener = Database::from(database.to_str().unwrap());
        if cache_size == 0 {
            opener = opener.no_cache();
        } else {
            opener = opener.cache_capacity(cache_size);
        }
        opener
            .open()
            .with_context(|| format!("Failed to load database: {}", database.display()))?
    };
    let load_time = load_start.elapsed();

    // Info messages to stderr
    if show_stats {
        if is_from_source.is_some() {
            eprintln!("[INFO] Built database from: {}", database.display());
        } else {
            eprintln!("[INFO] Loaded database: {}", database.display());
        }
        eprintln!("[INFO] Load time: {:.2}ms", load_time.as_millis());
        eprintln!(
            "[INFO] Cache: {}",
            if cache_size == 0 {
                "disabled".to_string()
            } else {
                format!("{} entries", cache_size)
            }
        );
    }

    // Parse extractor configuration from CLI flags
    use crate::match_processor::ExtractorConfig;
    let extractor_config = ExtractorConfig::from_arg(extractors_arg.clone());

    // Configure extractor based on database capabilities and CLI flags
    let has_ip = db.has_ip_data();
    let has_strings = db.has_literal_data() || db.has_glob_data();

    // Determine defaults based on whether user specified explicit includes
    // If user says --extractors=ip,domain (positive), ONLY enable those (exclusive mode)
    // If user says --extractors=-crypto (negative), enable all defaults except those
    let use_defaults = !extractor_config.has_explicit_enables();

    let default_ipv4 = use_defaults && has_ip;
    let default_ipv6 = use_defaults && has_ip;
    let default_domains = use_defaults && has_strings;
    let default_emails = use_defaults && has_strings;
    let default_hashes = use_defaults && has_strings;
    let default_bitcoin = use_defaults && has_strings;
    let default_ethereum = use_defaults && has_strings;
    let default_monero = use_defaults && has_strings;

    // Build extractor with CLI overrides
    let builder = Extractor::builder()
        .extract_ipv4(extractor_config.should_enable("ipv4", default_ipv4))
        .extract_ipv6(extractor_config.should_enable("ipv6", default_ipv6))
        .extract_domains(extractor_config.should_enable("domain", default_domains))
        .extract_emails(extractor_config.should_enable("email", default_emails))
        .extract_hashes(extractor_config.should_enable("hash", default_hashes))
        .extract_bitcoin(extractor_config.should_enable("bitcoin", default_bitcoin))
        .extract_ethereum(extractor_config.should_enable("ethereum", default_ethereum))
        .extract_monero(extractor_config.should_enable("monero", default_monero));

    let extractor = builder
        .build()
        .context("Failed to create pattern extractor")?;

    if show_stats {
        // Build list of enabled extractors
        let mut enabled = Vec::new();
        if extractor.extract_ipv4() {
            enabled.push("IPv4");
        }
        if extractor.extract_ipv6() {
            enabled.push("IPv6");
        }
        if extractor.extract_domains() {
            enabled.push("domains");
        }
        if extractor.extract_emails() {
            enabled.push("emails");
        }
        if extractor.extract_hashes() {
            enabled.push("hashes");
        }
        if extractor.extract_bitcoin() {
            enabled.push("Bitcoin");
        }
        if extractor.extract_ethereum() {
            enabled.push("Ethereum");
        }
        if extractor.extract_monero() {
            enabled.push("Monero");
        }

        eprintln!(
            "[INFO] Extractors: {}",
            if enabled.is_empty() {
                "none".to_string()
            } else {
                enabled.join(", ")
            }
        );
    }

    // Wrap database in Arc for sharing across parallel workers
    let db = Arc::new(db);

    // Setup Ctrl+C handler for follow mode
    let shutdown = Arc::new(AtomicBool::new(false));
    if follow {
        if show_stats {
            eprintln!("[INFO] Mode: Follow (watch files for new content)");
        }
        let shutdown_clone = Arc::clone(&shutdown);
        ctrlc::set_handler(move || {
            eprintln!("\n[INFO] Shutting down...");
            shutdown_clone.store(true, Ordering::Relaxed);
        })
        .context("Failed to set Ctrl+C handler")?;
    }

    // Validate input
    if inputs.is_empty() {
        anyhow::bail!("No input files specified");
    }

    // Process files
    let overall_start = Instant::now();
    let aggregate_stats: ProcessingStats;
    let files_processed: usize;
    let files_failed: usize;
    let actual_workers: usize; // Actual worker count (may differ from num_threads in auto-tune)
    let actual_readers: usize; // Actual reader count
    let routing_stats: Option<matchy::processing::RoutingStats>; // Routing decisions (parallel mode only)
    let is_auto_tuned = num_threads == 0; // Track if auto-tune was used

    // Check for compressed files
    let _has_compressed: bool = inputs.iter().any(|p| {
        p.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("gz") || e.eq_ignore_ascii_case("bz2"))
            .unwrap_or(false)
    });

    if follow {
        // Follow mode - use parallel or sequential based on thread count
        if num_threads > 1 {
            if show_stats {
                eprintln!(
                    "[INFO] Using parallel follow with {} worker threads",
                    num_threads
                );
            }
            aggregate_stats = follow_files_parallel(
                inputs.clone(),
                Arc::clone(&db),
                num_threads,
                &format,
                show_stats,
                show_progress,
                overall_start,
                shutdown,
                extractor_config,
            )?;
            actual_workers = num_threads;
            actual_readers = 1; // Follow mode uses single reader
            routing_stats = None;
        } else {
            if show_stats {
                eprintln!("[INFO] Using sequential follow (single-threaded)");
            }
            aggregate_stats = follow_files(
                inputs.clone(),
                &db,
                &extractor,
                &format,
                show_stats,
                show_progress,
                overall_start,
                shutdown,
            )?;
            actual_workers = 1;
            actual_readers = 1;
            routing_stats = None;
        }
        files_processed = inputs.len();
        files_failed = 0;
    } else if num_threads == 0 || num_threads > 1 {
        // Parallel mode (num_threads=0 means auto-tune, >1 means explicit count)
        let (stats, workers, readers, rstats) = process_parallel(
            inputs.clone(),
            Arc::clone(&db),
            num_threads,
            readers_arg,
            batch_bytes,
            &format,
            show_stats,
            show_progress,
            overall_start,
            extractor_config,
            debug_routing,
        )?;
        aggregate_stats = stats;
        actual_workers = workers;
        actual_readers = readers;
        routing_stats = Some(rstats);
        files_processed = inputs.len();
        files_failed = 0;
    } else {
        // Sequential mode
        let mut seq_stats = ProcessingStats::new();
        let mut seq_processed = 0;
        let mut seq_failed = 0;
        let mut stdin_already_processed = false;

        // Initialize progress reporter for aggregate progress across files
        let mut progress = if show_progress {
            Some(crate::match_processor::ProgressReporter::new())
        } else {
            None
        };

        for input_path in &inputs {
            // Handle stdin (allow "-" only once)
            if input_path.to_str() == Some("-") {
                if stdin_already_processed {
                    if show_stats {
                        eprintln!("[WARN] Skipping duplicate stdin argument");
                    }
                    continue;
                }
                stdin_already_processed = true;
            }

            // Process this file with aggregate progress tracking
            match process_file_with_aggregate(
                input_path,
                &db,
                &extractor,
                &format,
                show_stats,
                &mut seq_stats,
                &mut progress,
                overall_start,
            ) {
                Ok(()) => {
                    seq_processed += 1;
                }
                Err(e) => {
                    eprintln!("[ERROR] Failed to process {}: {}", input_path.display(), e);
                    seq_failed += 1;
                }
            }
        }

        // Add final newline if progress was shown
        if progress.is_some() {
            eprintln!();
        }

        aggregate_stats = seq_stats;
        actual_workers = 1; // Sequential mode
        actual_readers = 1;
        routing_stats = None;
        files_processed = seq_processed;
        files_failed = seq_failed;
    }

    let overall_elapsed = overall_start.elapsed();

    // Output aggregate summary stats to stderr
    if show_stats {
        let db_stats = db.stats();

        eprintln!();
        eprintln!("[INFO] === Processing Complete ===");
        if inputs.len() > 1 {
            eprintln!("[INFO] Files processed: {}", files_processed);
            if files_failed > 0 {
                eprintln!("[INFO] Files failed: {}", files_failed);
            }
        }
        eprintln!(
            "[INFO] Lines processed: {}",
            format_number(aggregate_stats.lines_processed)
        );
        eprintln!(
            "[INFO] Lines with matches: {} ({:.1}%)",
            format_number(aggregate_stats.lines_with_matches),
            if aggregate_stats.lines_processed > 0 {
                (aggregate_stats.lines_with_matches as f64 / aggregate_stats.lines_processed as f64)
                    * 100.0
            } else {
                0.0
            }
        );
        eprintln!(
            "[INFO] Total matches: {}",
            format_number(aggregate_stats.total_matches)
        );
        eprintln!(
            "[INFO] Candidates tested: {}",
            format_number(aggregate_stats.candidates_tested)
        );

        if aggregate_stats.ipv4_count > 0 {
            eprintln!(
                "[INFO]   IPv4: {}",
                format_number(aggregate_stats.ipv4_count)
            );
        }
        if aggregate_stats.ipv6_count > 0 {
            eprintln!(
                "[INFO]   IPv6: {}",
                format_number(aggregate_stats.ipv6_count)
            );
        }
        if aggregate_stats.domain_count > 0 {
            eprintln!(
                "[INFO]   Domains: {}",
                format_number(aggregate_stats.domain_count)
            );
        }
        if aggregate_stats.email_count > 0 {
            eprintln!(
                "[INFO]   Emails: {}",
                format_number(aggregate_stats.email_count)
            );
        }

        eprintln!(
            "[INFO] Throughput: {:.2} MB/s",
            if overall_elapsed.as_secs_f64() > 0.0 {
                (aggregate_stats.total_bytes as f64 / 1_000_000.0) / overall_elapsed.as_secs_f64()
            } else {
                0.0
            }
        );
        eprintln!("[INFO] Total time: {:.2}s", overall_elapsed.as_secs_f64());
        eprintln!(
            "[INFO] Extraction time (sampled): {:.2}s ({:.2}µs per sample, {} samples)",
            aggregate_stats.extraction_time.as_secs_f64(),
            if aggregate_stats.extraction_samples > 0 {
                aggregate_stats.extraction_time.as_nanos() as f64
                    / 1000.0
                    / aggregate_stats.extraction_samples as f64
            } else {
                0.0
            },
            format_number(aggregate_stats.extraction_samples)
        );
        eprintln!(
            "[INFO] Lookup time (sampled): {:.2}s ({:.2}µs per sample, {} samples)",
            aggregate_stats.lookup_time.as_secs_f64(),
            if aggregate_stats.lookup_samples > 0 {
                aggregate_stats.lookup_time.as_nanos() as f64
                    / 1000.0
                    / aggregate_stats.lookup_samples as f64
            } else {
                0.0
            },
            format_number(aggregate_stats.lookup_samples)
        );

        eprintln!(
            "[INFO] Query rate: {} queries/s",
            format_qps(if overall_elapsed.as_secs_f64() > 0.0 {
                aggregate_stats.candidates_tested as f64 / overall_elapsed.as_secs_f64()
            } else {
                0.0
            })
        );

        if cache_size > 0 {
            eprintln!(
                "[INFO] Cache: {} entries ({:.1}% hit rate)",
                format_number(cache_size),
                db_stats.cache_hit_rate() * 100.0
            );
        }

        // Show thread allocation (parallel mode only)
        if actual_readers > 0 || actual_workers > 0 {
            eprintln!();
            eprintln!("[INFO] === Thread Allocation ===");
            eprintln!("[INFO] Reader threads spawned: {}", actual_readers);
            eprintln!("[INFO] Worker threads spawned: {}", actual_workers);
        }

        // Show routing statistics if available (parallel mode only)
        if let Some(ref rstats) = routing_stats {
            eprintln!();
            eprintln!("[INFO] === File Routing ===");
            eprintln!(
                "[INFO] Files to workers (whole): {}",
                rstats.files_to_workers
            );
            eprintln!(
                "[INFO] Files to readers (chunked): {}",
                rstats.files_to_readers
            );
            if rstats.total_bytes() > 0 {
                let mb = |b: u64| b as f64 / (1024.0 * 1024.0);
                eprintln!(
                    "[INFO] Data: {:.2} MB to workers, {:.2} MB to readers",
                    mb(rstats.bytes_to_workers),
                    mb(rstats.bytes_to_readers)
                );
            }
        }

        // Bottleneck analysis (only for parallel mode with timing data)
        if actual_workers > 1 && overall_elapsed.as_secs_f64() > 0.1 {
            eprintln!();
            eprintln!("[INFO] === Performance Analysis ===");

            let config = crate::match_processor::AnalysisConfig {
                num_workers: actual_workers,
                num_files: inputs.len(),
                cache_hit_rate: db_stats.cache_hit_rate(),
                is_auto_tuned,
                num_readers: actual_readers,
            };

            let analysis = analyze_performance(&aggregate_stats, overall_elapsed, config);

            // Show bottleneck and recommendations
            eprintln!();
            eprintln!("[INFO] {}", analysis.explanation);
            if !analysis.recommendations.is_empty() {
                for rec in &analysis.recommendations {
                    eprintln!("[INFO] → {}", rec);
                }
            }
        }
    }

    // Return error code if any files failed
    if files_failed > 0 {
        anyhow::bail!("{} file(s) failed to process", files_failed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_is_source_file_json() {
        assert_eq!(is_source_file(Path::new("test.json")), Some("json"));
        assert_eq!(is_source_file(Path::new("test.JSON")), Some("json"));
        assert_eq!(
            is_source_file(Path::new("/path/to/file.Json")),
            Some("json")
        );
    }

    #[test]
    fn test_is_source_file_csv() {
        assert_eq!(is_source_file(Path::new("test.csv")), Some("csv"));
        assert_eq!(is_source_file(Path::new("test.CSV")), Some("csv"));
        assert_eq!(is_source_file(Path::new("/path/to/file.Csv")), Some("csv"));
    }

    #[test]
    fn test_is_source_file_other() {
        assert_eq!(is_source_file(Path::new("test.mxy")), None);
        assert_eq!(is_source_file(Path::new("test.txt")), None);
        assert_eq!(is_source_file(Path::new("test")), None);
        assert_eq!(is_source_file(Path::new("")), None);
    }

    #[test]
    fn test_build_database_from_json() {
        let temp_dir = TempDir::new().unwrap();
        let json_path = temp_dir.path().join("test.json");

        let json_content = r#"[
            {"key": "192.168.1.0/24", "data": {"type": "internal"}},
            {"key": "*.malware.com", "data": {"severity": "high"}},
            {"key": "evil.com"}
        ]"#;
        fs::write(&json_path, json_content).unwrap();

        let result = build_database_from_source(&json_path, "json", false);
        assert!(result.is_ok(), "Should build database from JSON");
        let db_bytes = result.unwrap();
        assert!(!db_bytes.is_empty(), "Database should not be empty");
    }

    #[test]
    fn test_build_database_from_json_with_stats() {
        let temp_dir = TempDir::new().unwrap();
        let json_path = temp_dir.path().join("test.json");

        let json_content = r#"[{"key": "test.com"}]"#;
        fs::write(&json_path, json_content).unwrap();

        // Should not panic with stats enabled
        let result = build_database_from_source(&json_path, "json", true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_database_from_json_missing_key() {
        let temp_dir = TempDir::new().unwrap();
        let json_path = temp_dir.path().join("test.json");

        let json_content = r#"[{"data": {"type": "internal"}}]"#;
        fs::write(&json_path, json_content).unwrap();

        let result = build_database_from_source(&json_path, "json", false);
        assert!(result.is_err(), "Should fail without 'key' field");
        assert!(result.unwrap_err().to_string().contains("key"));
    }

    #[test]
    fn test_build_database_from_json_invalid() {
        let temp_dir = TempDir::new().unwrap();
        let json_path = temp_dir.path().join("test.json");

        fs::write(&json_path, "{ not valid json }").unwrap();

        let result = build_database_from_source(&json_path, "json", false);
        assert!(result.is_err(), "Should fail on invalid JSON");
    }

    #[test]
    fn test_build_database_from_csv() {
        let temp_dir = TempDir::new().unwrap();
        let csv_path = temp_dir.path().join("test.csv");

        let csv_content =
            "key,type,severity\n192.168.1.0/24,internal,low\n*.malware.com,malware,high\n";
        fs::write(&csv_path, csv_content).unwrap();

        let result = build_database_from_source(&csv_path, "csv", false);
        assert!(result.is_ok(), "Should build database from CSV");
        let db_bytes = result.unwrap();
        assert!(!db_bytes.is_empty(), "Database should not be empty");
    }

    #[test]
    fn test_build_database_from_csv_entry_column() {
        let temp_dir = TempDir::new().unwrap();
        let csv_path = temp_dir.path().join("test.csv");

        // Using 'entry' instead of 'key'
        let csv_content = "entry,type\ntest.com,phishing\n";
        fs::write(&csv_path, csv_content).unwrap();

        let result = build_database_from_source(&csv_path, "csv", false);
        assert!(result.is_ok(), "Should accept 'entry' column");
    }

    #[test]
    fn test_build_database_from_csv_missing_key_column() {
        let temp_dir = TempDir::new().unwrap();
        let csv_path = temp_dir.path().join("test.csv");

        let csv_content = "type,severity\nmalware,high\n";
        fs::write(&csv_path, csv_content).unwrap();

        let result = build_database_from_source(&csv_path, "csv", false);
        assert!(
            result.is_err(),
            "Should fail without 'key' or 'entry' column"
        );
        let err = result.unwrap_err().to_string();
        assert!(err.contains("entry") || err.contains("key"));
    }

    #[test]
    fn test_build_database_from_csv_numeric_values() {
        let temp_dir = TempDir::new().unwrap();
        let csv_path = temp_dir.path().join("test.csv");

        // Test various data types in CSV
        let csv_content = "key,count,score,active\ntest.com,42,3.14,true\n";
        fs::write(&csv_path, csv_content).unwrap();

        let result = build_database_from_source(&csv_path, "csv", false);
        assert!(result.is_ok(), "Should handle numeric and boolean values");
    }

    #[test]
    fn test_build_database_from_text() {
        let temp_dir = TempDir::new().unwrap();
        let txt_path = temp_dir.path().join("test.txt");

        let txt_content = "192.168.1.0/24\n*.malware.com\n# comment\n\nevil.com\n";
        fs::write(&txt_path, txt_content).unwrap();

        let result = build_database_from_source(&txt_path, "text", false);
        assert!(result.is_ok(), "Should build database from text file");
    }

    #[test]
    fn test_build_database_unknown_format() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test.xyz");
        fs::write(&path, "test").unwrap();

        let result = build_database_from_source(&path, "xyz", false);
        assert!(result.is_err(), "Should fail on unknown format");
        assert!(result.unwrap_err().to_string().contains("Unknown format"));
    }

    #[test]
    fn test_build_database_file_not_found() {
        let result = build_database_from_source(Path::new("/nonexistent/file.json"), "json", false);
        assert!(result.is_err(), "Should fail on missing file");
    }
}
