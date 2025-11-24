use anyhow::{Context, Result};
use serde_json::json;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::time::Instant;

use crate::cli_utils::{data_value_to_json, format_cidr};

use super::stats::{ProcessingStats, ProgressReporter};

const BUFFER_SIZE: usize = 128 * 1024; // 128KB buffer
const BATCH_SIZE: usize = 16; // Process 16 lines at a time
const SAMPLE_INTERVAL: usize = 100;
const RESYNC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Batched line processor - zero-copy slicing of buffer into line references
struct BatchedLineProcessor<R: io::BufRead> {
    reader: R,
    partial: Vec<u8>,
    eof: bool,
}

impl<R: io::BufRead> BatchedLineProcessor<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            partial: Vec::new(),
            eof: false,
        }
    }

    /// Read up to batch_size lines as slices from the internal buffer
    /// Returns (lines, line_numbers_start, total_bytes)
    /// 
    /// This is zero-copy when lines fit in the buffer - we just create &[u8] slices
    fn read_batch(&mut self, batch_size: usize, current_line: usize) -> io::Result<(Vec<Vec<u8>>, usize, usize)> {
        let mut lines = Vec::with_capacity(batch_size);
        let mut total_bytes = 0;
        let start_line = current_line;

        for _ in 0..batch_size {
            if self.eof && self.partial.is_empty() {
                break;
            }

            let mut line_buf = Vec::new();
            if !self.read_line(&mut line_buf)? {
                break;
            }

            total_bytes += line_buf.len();
            lines.push(line_buf);
        }

        Ok((lines, start_line, total_bytes))
    }

    /// Read a single line into buffer (copied from LineScanner but without trimming for now)
    fn read_line(&mut self, line_buf: &mut Vec<u8>) -> io::Result<bool> {
        line_buf.clear();

        loop {
            if self.eof {
                if !self.partial.is_empty() {
                    line_buf.extend_from_slice(&self.partial);
                    self.partial.clear();
                    return Ok(true);
                }
                return Ok(false);
            }

            let buffer = self.reader.fill_buf()?;

            if buffer.is_empty() {
                self.eof = true;
                continue;
            }

            // Find newline
            if let Some(newline_pos) = memchr::memchr(b'\n', buffer) {
                if self.partial.is_empty() {
                    // Fast path: complete line in buffer
                    line_buf.extend_from_slice(&buffer[..newline_pos]);
                    self.reader.consume(newline_pos + 1);
                    return Ok(true);
                } else {
                    // Complete partial line
                    self.partial.extend_from_slice(&buffer[..newline_pos]);
                    line_buf.extend_from_slice(&self.partial);
                    self.partial.clear();
                    self.reader.consume(newline_pos + 1);
                    return Ok(true);
                }
            } else {
                // No newline - accumulate
                self.partial.extend_from_slice(buffer);
                let consumed = buffer.len();
                self.reader.consume(consumed);
            }
        }
    }
}

/// Process file with batched domain extraction
#[allow(clippy::too_many_arguments)]
pub fn process_file_batched(
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

    let mut progress = if show_progress {
        Some(ProgressReporter::new())
    } else {
        None
    };

    let mut base_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let mut last_resync = Instant::now();

    let mut processor = BatchedLineProcessor::new(reader);

    loop {
        // Read a batch of lines
        let (lines, start_line_num, batch_bytes) = processor.read_batch(BATCH_SIZE, stats.lines_processed + 1)?;
        
        if lines.is_empty() {
            break;
        }

        stats.lines_processed += lines.len();
        stats.total_bytes += batch_bytes;

        // Batch domain extraction ONLY - this is where the speedup comes from
        // Other extraction (IPv4/IPv6/Email) is fast with memchr, extract lazily per-line
        let extract_start = if show_stats {
            Some(Instant::now())
        } else {
            None
        };

        // Create slice references for batching (zero-copy)
        let line_refs: Vec<&[u8]> = lines.iter().map(|v| v.as_slice()).collect();
        
        // Batch domain extraction (uses AC automaton - 1.5-3x faster)
        let domain_batches = if extractor.extract_domains() {
            extractor.extract_domains_batch(&line_refs)
        } else {
            vec![Vec::new(); lines.len()]
        };

        if let Some(start) = extract_start {
            stats.extraction_time += start.elapsed();
            stats.extraction_samples += 1;
        }

        // Process each line with its pre-computed results
        for (line_idx, line_buf) in lines.iter().enumerate() {
            let line_number = start_line_num + line_idx;

            // Resync wall clock periodically
            if output_json && line_number % 6000 == 0 {
                let now = Instant::now();
                if now.duration_since(last_resync) >= RESYNC_INTERVAL {
                    base_timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs_f64()
                        - overall_start.elapsed().as_secs_f64();
                    last_resync = now;
                }
            }

            let timestamp = if output_json {
                base_timestamp + overall_start.elapsed().as_secs_f64()
            } else {
                0.0
            };

            let mut line_had_match = false;

            // Process domain matches (from batch)
            for domain_match in &domain_batches[line_idx] {
                stats.candidates_tested += 1;
                if show_stats {
                    stats.domain_count += 1;
                }

                let domain_str = match &domain_match.item {
                    matchy::extractor::ExtractedItem::Domain(d) => d,
                    _ => continue,
                };

                // Lookup
                let lookup_start = if show_stats && stats.candidates_tested % SAMPLE_INTERVAL == 0 {
                    Some(Instant::now())
                } else {
                    None
                };

                let result = db.lookup(domain_str)?;

                if let Some(start) = lookup_start {
                    stats.lookup_time += start.elapsed();
                    stats.lookup_samples += 1;
                }

                let is_match = matches!(
                    &result,
                    Some(matchy::QueryResult::Pattern { pattern_ids, .. }) if !pattern_ids.is_empty()
                );

                if is_match {
                    if !line_had_match {
                        stats.lines_with_matches += 1;
                        line_had_match = true;
                    }
                    stats.total_matches += 1;

                    if output_json {
                        output_match_json(
                            &result,
                            domain_str,
                            line_buf,
                            line_number,
                            timestamp,
                            input_path,
                        )?;
                    }
                }
            }

            // Extract and process other candidates (IP, email) - lazy extraction per line
            let other_matches = extractor
                .extract_from_line(line_buf)
                .filter(|m| !matches!(m.item, matchy::extractor::ExtractedItem::Domain(_)));
            
            for item in other_matches {
                stats.candidates_tested += 1;

                if show_stats {
                    match &item.item {
                        matchy::extractor::ExtractedItem::Ipv4(_) => stats.ipv4_count += 1,
                        matchy::extractor::ExtractedItem::Ipv6(_) => stats.ipv6_count += 1,
                        matchy::extractor::ExtractedItem::Email(_) => stats.email_count += 1,
                        matchy::extractor::ExtractedItem::Hash(_, _) => {},
                        matchy::extractor::ExtractedItem::Bitcoin(_) => {},
                        matchy::extractor::ExtractedItem::Ethereum(_) => {},
                        matchy::extractor::ExtractedItem::Monero(_) => {},
                        _ => {}
                    }
                }

                // Lookup FIRST, then convert to string ONLY if match
                // This avoids allocating strings for non-matches
                let result = match &item.item {
                    matchy::extractor::ExtractedItem::Ipv4(ip) => db.lookup_ip(IpAddr::V4(*ip))?,
                    matchy::extractor::ExtractedItem::Ipv6(ip) => db.lookup_ip(IpAddr::V6(*ip))?,
                    matchy::extractor::ExtractedItem::Email(s)
                    | matchy::extractor::ExtractedItem::Hash(_, s)
                    | matchy::extractor::ExtractedItem::Bitcoin(s)
                    | matchy::extractor::ExtractedItem::Ethereum(s)
                    | matchy::extractor::ExtractedItem::Monero(s) => db.lookup(s)?,
                    _ => continue,
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

                    if output_json {
                        // Only allocate string for matches that need output
                        let candidate_str = item.item.as_value();
                        
                        output_match_json(
                            &result,
                            &candidate_str,
                            line_buf,
                            line_number,
                            timestamp,
                            input_path,
                        )?;
                    }
                }
            }
        }

        // Show progress
        if let Some(ref mut prog) = progress {
            if prog.should_update() {
                prog.show(&stats, overall_start.elapsed());
            }
        }
    }

    Ok(stats)
}

fn output_match_json(
    result: &Option<matchy::QueryResult>,
    candidate_str: &str,
    line_buf: &[u8],
    line_number: usize,
    timestamp: f64,
    input_path: &Path,
) -> Result<()> {
    // Use Cow to avoid allocation when UTF-8 is valid (most log lines are)
    // Only allocates when invalid UTF-8 needs replacement
    use std::borrow::Cow;
    let input_line: Cow<str> = String::from_utf8_lossy(line_buf);
    
    let mut match_obj = json!({
        "timestamp": format!("{:.3}", timestamp),
        "source": input_path.display().to_string(),
        "matched_text": candidate_str,
    });

    match result {
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
            match_obj["cidr"] = json!(format_cidr(candidate_str, *prefix_len));
            match_obj["data"] = data_value_to_json(data);
        }
        _ => {}
    }

    println!("{}", serde_json::to_string(&match_obj)?);
    Ok(())
}
