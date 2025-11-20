use anyhow::{Context, Result};
use serde_json::json;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::time::Instant;

use crate::cli_utils::{data_value_to_json, format_cidr, LineScanner};

use super::stats::{ProcessingStats, ProgressReporter};

const BUFFER_SIZE: usize = 128 * 1024; // 128KB buffer
const SAMPLE_INTERVAL: usize = 100; // Sample timing every N lines/candidates
const RESYNC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Process a single file (or stdin) and return statistics
pub fn process_file(
    input_path: &Path,
    db: &matchy::Database,
    extractor: &matchy::extractor::Extractor,
    output_format: &str,
    show_stats: bool,
    show_progress: bool,
    overall_start: Instant,
) -> Result<ProcessingStats> {
    let reader: Box<dyn io::BufRead> = if input_path.to_str() == Some("-") {
        Box::new(io::BufReader::with_capacity(BUFFER_SIZE, io::stdin()))
    } else {
        Box::new(io::BufReader::with_capacity(
            BUFFER_SIZE,
            fs::File::open(input_path)
                .with_context(|| format!("Failed to open input file: {}", input_path.display()))?,
        ))
    };

    let mut stats = ProcessingStats::new();
    let output_json = output_format == "json";

    // Initialize progress reporter
    let mut progress = if show_progress {
        Some(super::stats::ProgressReporter::new())
    } else {
        None
    };

    // Get base timestamp once, use monotonic clock for offsets
    let mut base_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let mut last_resync = Instant::now();

    // Process lines using LineScanner
    let mut scanner = LineScanner::new(reader);
    let mut line_buf = Vec::new();

    while scanner.read_line(&mut line_buf)? {
        stats.lines_processed += 1;
        stats.total_bytes += line_buf.len();

        // Calculate timestamp from monotonic clock offset
        let timestamp = if output_json {
            base_timestamp + overall_start.elapsed().as_secs_f64()
        } else {
            0.0
        };

        // Extract candidates from the line
        let extract_start = if show_stats && stats.lines_processed.is_multiple_of(SAMPLE_INTERVAL) {
            Some(Instant::now())
        } else {
            None
        };

        // Resync wall clock periodically
        let should_check_resync =
            extract_start.is_some() || stats.lines_processed.is_multiple_of(6000);
        if output_json && should_check_resync {
            let now = extract_start.unwrap_or_else(Instant::now);
            if now.duration_since(last_resync) >= RESYNC_INTERVAL {
                base_timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs_f64()
                    - overall_start.elapsed().as_secs_f64();
                last_resync = now;
            }
        }

        let extracted = extractor.extract_from_line(&line_buf);
        if let Some(start) = extract_start {
            stats.extraction_time += start.elapsed();
            stats.extraction_samples += 1;
        }

        let mut line_had_match = false;

        // Test each candidate
        for item in extracted {
            stats.candidates_tested += 1;

            // Track candidate types if stats enabled
            if show_stats {
                match &item.item {
                    matchy::extractor::ExtractedItem::Ipv4(_) => stats.ipv4_count += 1,
                    matchy::extractor::ExtractedItem::Ipv6(_) => stats.ipv6_count += 1,
                    matchy::extractor::ExtractedItem::Domain(_) => stats.domain_count += 1,
                    matchy::extractor::ExtractedItem::Email(_) => stats.email_count += 1,
                    matchy::extractor::ExtractedItem::Hash(_, _) => {}
                    matchy::extractor::ExtractedItem::Bitcoin(_) => {}
                    matchy::extractor::ExtractedItem::Ethereum(_) => {}
                    matchy::extractor::ExtractedItem::Monero(_) => {}
                }
            }

            // Lookup candidate
            let lookup_start =
                if show_stats && stats.candidates_tested.is_multiple_of(SAMPLE_INTERVAL) {
                    Some(Instant::now())
                } else {
                    None
                };
            let candidate_str = item.item.as_value();
            let result = match item.item {
                matchy::extractor::ExtractedItem::Ipv4(ip) => db.lookup_ip(IpAddr::V4(ip))?,
                matchy::extractor::ExtractedItem::Ipv6(ip) => db.lookup_ip(IpAddr::V6(ip))?,
                matchy::extractor::ExtractedItem::Domain(s)
                | matchy::extractor::ExtractedItem::Email(s)
                | matchy::extractor::ExtractedItem::Hash(_, s)
                | matchy::extractor::ExtractedItem::Bitcoin(s)
                | matchy::extractor::ExtractedItem::Ethereum(s)
                | matchy::extractor::ExtractedItem::Monero(s) => db.lookup(s)?,
            };
            if let Some(start) = lookup_start {
                stats.lookup_time += start.elapsed();
                stats.lookup_samples += 1;
            }

            let is_match = match &result {
                Some(matchy::QueryResult::Pattern { pattern_ids, .. }) => !pattern_ids.is_empty(),
                Some(matchy::QueryResult::Ip { .. }) => true,
                _ => false,
            };

            if is_match {
                if !line_had_match {
                    stats.lines_with_matches += 1;
                    line_had_match = true;
                }
                stats.total_matches += 1;

                // Output match to stdout as NDJSON
                if output_json {
                    let mut match_obj = json!({
                        "timestamp": format!("{:.3}", timestamp),
                        "source": input_path.display().to_string(),
                        "matched_text": candidate_str,
                    });

                    // Add match-specific fields
                    match &result {
                        Some(matchy::QueryResult::Pattern { pattern_ids, data }) => {
                            match_obj["match_type"] = json!("pattern");
                            match_obj["pattern_count"] = json!(pattern_ids.len());
                            if !data.is_empty() {
                                let data_json: Vec<_> = data
                                    .iter()
                                    .filter_map(|d| d.as_ref().map(data_value_to_json))
                                    .collect();
                                if !data_json.is_empty() {
                                    match_obj["data"] = json!(data_json);
                                }
                            }
                        }
                        Some(matchy::QueryResult::Ip { data, prefix_len }) => {
                            match_obj["match_type"] = json!("ip");
                            match_obj["prefix_len"] = json!(prefix_len);
                            match_obj["cidr"] = json!(format_cidr(&candidate_str, *prefix_len));
                            match_obj["data"] = data_value_to_json(data);
                        }
                        _ => {}
                    }

                    // Write to stdout
                    println!("{}", serde_json::to_string(&match_obj)?);
                }
            }
        }

        // Show progress if enabled
        if let Some(ref mut prog) = progress {
            if prog.should_update() {
                prog.show(&stats, overall_start.elapsed());
            }
        }
    }

    Ok(stats)
}

/// Process a single file with cumulative progress tracking
/// Updates aggregate_stats in place and uses shared progress reporter
#[allow(clippy::too_many_arguments)]
pub fn process_file_with_aggregate(
    input_path: &Path,
    db: &matchy::Database,
    extractor: &matchy::extractor::Extractor,
    output_format: &str,
    show_stats: bool,
    aggregate_stats: &mut ProcessingStats,
    progress: &mut Option<ProgressReporter>,
    overall_start: Instant,
) -> Result<()> {
    let reader: Box<dyn io::BufRead> = if input_path.to_str() == Some("-") {
        Box::new(io::BufReader::with_capacity(BUFFER_SIZE, io::stdin()))
    } else {
        Box::new(io::BufReader::with_capacity(
            BUFFER_SIZE,
            fs::File::open(input_path)
                .with_context(|| format!("Failed to open input file: {}", input_path.display()))?,
        ))
    };

    let output_json = output_format == "json";

    // Get base timestamp once, use monotonic clock for offsets
    let mut base_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let mut last_resync = Instant::now();

    // Process lines using LineScanner
    let mut scanner = LineScanner::new(reader);
    let mut line_buf = Vec::new();

    while scanner.read_line(&mut line_buf)? {
        aggregate_stats.lines_processed += 1;
        aggregate_stats.total_bytes += line_buf.len();

        // Calculate timestamp from monotonic clock offset
        let timestamp = if output_json {
            base_timestamp + overall_start.elapsed().as_secs_f64()
        } else {
            0.0
        };

        // Extract candidates from the line
        let extract_start = if show_stats
            && aggregate_stats
                .lines_processed
                .is_multiple_of(SAMPLE_INTERVAL)
        {
            Some(Instant::now())
        } else {
            None
        };

        // Resync wall clock periodically
        let should_check_resync =
            extract_start.is_some() || aggregate_stats.lines_processed.is_multiple_of(6000);
        if output_json && should_check_resync {
            let now = extract_start.unwrap_or_else(Instant::now);
            if now.duration_since(last_resync) >= RESYNC_INTERVAL {
                base_timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs_f64()
                    - overall_start.elapsed().as_secs_f64();
                last_resync = now;
            }
        }

        let extracted = extractor.extract_from_line(&line_buf);
        if let Some(start) = extract_start {
            aggregate_stats.extraction_time += start.elapsed();
            aggregate_stats.extraction_samples += 1;
        }

        let mut line_had_match = false;

        // Test each candidate
        for item in extracted {
            aggregate_stats.candidates_tested += 1;

            // Track candidate types (for stats or progress display)
            match &item.item {
                matchy::extractor::ExtractedItem::Ipv4(_) => aggregate_stats.ipv4_count += 1,
                matchy::extractor::ExtractedItem::Ipv6(_) => aggregate_stats.ipv6_count += 1,
                matchy::extractor::ExtractedItem::Domain(_) => aggregate_stats.domain_count += 1,
                matchy::extractor::ExtractedItem::Email(_) => aggregate_stats.email_count += 1,
                matchy::extractor::ExtractedItem::Hash(_, _) => {}
                matchy::extractor::ExtractedItem::Bitcoin(_) => {}
                matchy::extractor::ExtractedItem::Ethereum(_) => {}
                matchy::extractor::ExtractedItem::Monero(_) => {}
            }

            // Lookup candidate
            let lookup_start = if show_stats
                && aggregate_stats
                    .candidates_tested
                    .is_multiple_of(SAMPLE_INTERVAL)
            {
                Some(Instant::now())
            } else {
                None
            };
            let candidate_str = item.item.as_value();
            let result = match item.item {
                matchy::extractor::ExtractedItem::Ipv4(ip) => db.lookup_ip(IpAddr::V4(ip))?,
                matchy::extractor::ExtractedItem::Ipv6(ip) => db.lookup_ip(IpAddr::V6(ip))?,
                matchy::extractor::ExtractedItem::Domain(s)
                | matchy::extractor::ExtractedItem::Email(s)
                | matchy::extractor::ExtractedItem::Hash(_, s)
                | matchy::extractor::ExtractedItem::Bitcoin(s)
                | matchy::extractor::ExtractedItem::Ethereum(s)
                | matchy::extractor::ExtractedItem::Monero(s) => db.lookup(s)?,
            };
            if let Some(start) = lookup_start {
                aggregate_stats.lookup_time += start.elapsed();
                aggregate_stats.lookup_samples += 1;
            }

            let is_match = match &result {
                Some(matchy::QueryResult::Pattern { pattern_ids, .. }) => !pattern_ids.is_empty(),
                Some(matchy::QueryResult::Ip { .. }) => true,
                _ => false,
            };

            if is_match {
                if !line_had_match {
                    aggregate_stats.lines_with_matches += 1;
                    line_had_match = true;
                }
                aggregate_stats.total_matches += 1;

                // Output match to stdout as NDJSON
                if output_json {
                    let mut match_obj = json!({
                        "timestamp": format!("{:.3}", timestamp),
                        "source": input_path.display().to_string(),
                        "matched_text": candidate_str,
                    });

                    // Add match-specific fields
                    match &result {
                        Some(matchy::QueryResult::Pattern { pattern_ids, data }) => {
                            match_obj["match_type"] = json!("pattern");
                            match_obj["pattern_count"] = json!(pattern_ids.len());
                            if !data.is_empty() {
                                let data_json: Vec<_> = data
                                    .iter()
                                    .filter_map(|d| d.as_ref().map(data_value_to_json))
                                    .collect();
                                if !data_json.is_empty() {
                                    match_obj["data"] = json!(data_json);
                                }
                            }
                        }
                        Some(matchy::QueryResult::Ip { data, prefix_len }) => {
                            match_obj["match_type"] = json!("ip");
                            match_obj["prefix_len"] = json!(prefix_len);
                            match_obj["cidr"] = json!(format_cidr(&candidate_str, *prefix_len));
                            match_obj["data"] = data_value_to_json(data);
                        }
                        _ => {}
                    }

                    // Write to stdout
                    println!("{}", serde_json::to_string(&match_obj)?);
                }
            }
        }

        // Show progress if enabled (using aggregate stats)
        if let Some(ref mut prog) = progress {
            if prog.should_update() {
                prog.show(aggregate_stats, overall_start.elapsed());
            }
        }
    }

    // Add final newline if progress was shown
    if progress.is_some() {
        eprintln!();
    }

    Ok(())
}

/// Process matches for a single line (can be called from follow mode)
#[allow(clippy::too_many_arguments)]
pub fn process_line_matches(
    line_buf: &[u8],
    input_path: &Path,
    timestamp: f64,
    db: &matchy::Database,
    extractor: &matchy::extractor::Extractor,
    output_json: bool,
    stats: &mut ProcessingStats,
) -> Result<()> {
    let extracted = extractor.extract_from_line(line_buf);

    let mut line_had_match = false;

    // Test each candidate
    for item in extracted {
        stats.candidates_tested += 1;

        // Lookup candidate
        let candidate_str = item.item.as_value();
        let result = match item.item {
            matchy::extractor::ExtractedItem::Ipv4(ip) => db.lookup_ip(IpAddr::V4(ip))?,
            matchy::extractor::ExtractedItem::Ipv6(ip) => db.lookup_ip(IpAddr::V6(ip))?,
            matchy::extractor::ExtractedItem::Domain(s)
            | matchy::extractor::ExtractedItem::Email(s)
            | matchy::extractor::ExtractedItem::Hash(_, s)
            | matchy::extractor::ExtractedItem::Bitcoin(s)
            | matchy::extractor::ExtractedItem::Ethereum(s)
            | matchy::extractor::ExtractedItem::Monero(s) => db.lookup(s)?,
        };

        let is_match = match &result {
            Some(matchy::QueryResult::Pattern { pattern_ids, .. }) => !pattern_ids.is_empty(),
            Some(matchy::QueryResult::Ip { .. }) => true,
            _ => false,
        };

        if is_match {
            if !line_had_match {
                stats.lines_with_matches += 1;
                line_had_match = true;
            }
            stats.total_matches += 1;

            // Output match to stdout as NDJSON
            if output_json {
                let mut match_obj = json!({
                    "timestamp": format!("{:.3}", timestamp),
                    "source": input_path.display().to_string(),
                    "matched_text": candidate_str,
                });

                // Add match-specific fields
                match &result {
                    Some(matchy::QueryResult::Pattern { pattern_ids, data }) => {
                        match_obj["match_type"] = json!("pattern");
                        match_obj["pattern_count"] = json!(pattern_ids.len());
                        if !data.is_empty() {
                            let data_json: Vec<_> = data
                                .iter()
                                .filter_map(|d| d.as_ref().map(data_value_to_json))
                                .collect();
                            if !data_json.is_empty() {
                                match_obj["data"] = json!(data_json);
                            }
                        }
                    }
                    Some(matchy::QueryResult::Ip { data, prefix_len }) => {
                        match_obj["match_type"] = json!("ip");
                        match_obj["prefix_len"] = json!(prefix_len);
                        match_obj["cidr"] = json!(format_cidr(&candidate_str, *prefix_len));
                        match_obj["data"] = data_value_to_json(data);
                    }
                    _ => {}
                }

                // Write to stdout
                println!("{}", serde_json::to_string(&match_obj)?);
            }
        }
    }

    Ok(())
}
