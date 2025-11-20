use anyhow::{Context, Result};
use matchy::extractor::{ExtractedItem, Extractor};
use rustc_hash::FxHashSet;
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::Instant;

use crate::cli_utils::{format_number, LineScanner};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Json,
    Csv,
    Text,
}

impl OutputFormat {
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "csv" => Ok(Self::Csv),
            "text" => Ok(Self::Text),
            _ => anyhow::bail!("Invalid format '{}', expected: json, csv, or text", s),
        }
    }
}

#[derive(Default)]
struct ExtractionStats {
    lines_processed: usize,
    patterns_found: usize,
    ipv4_count: usize,
    ipv6_count: usize,
    domain_count: usize,
    email_count: usize,
    bytes_processed: usize,
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_extract(
    inputs: Vec<PathBuf>,
    format: String,
    types: Option<String>,
    min_labels: usize,
    no_boundaries: bool,
    unique: bool,
    threads: Option<String>,
    show_stats: bool,
    show_candidates: bool,
) -> Result<()> {
    // Parse format
    let output_format = OutputFormat::from_str(&format)?;

    // Parse extraction types
    let (extract_ipv4, extract_ipv6, extract_domains, extract_emails) =
        if let Some(type_str) = types {
            let types_lower = type_str.to_lowercase();
            let parts: Vec<&str> = types_lower.split(',').map(|s| s.trim()).collect();

            let mut ipv4 = false;
            let mut ipv6 = false;
            let mut domains = false;
            let mut emails = false;

            for part in parts {
                match part {
                    "ipv4" | "ip4" => ipv4 = true,
                    "ipv6" | "ip6" => ipv6 = true,
                    "domain" | "domains" => domains = true,
                    "email" | "emails" => emails = true,
                    "ip" => {
                        ipv4 = true;
                        ipv6 = true;
                    }
                    "all" => {
                        ipv4 = true;
                        ipv6 = true;
                        domains = true;
                        emails = true;
                    }
                    _ => anyhow::bail!(
                    "Unknown extraction type '{}', expected: ipv4, ipv6, ip, domain, email, all",
                    part
                ),
                }
            }

            if !ipv4 && !ipv6 && !domains && !emails {
                anyhow::bail!("At least one extraction type must be enabled");
            }

            (ipv4, ipv6, domains, emails)
        } else {
            // Default: extract everything
            (true, true, true, true)
        };

    // Build extractor
    let extractor = Extractor::builder()
        .extract_ipv4(extract_ipv4)
        .extract_ipv6(extract_ipv6)
        .extract_domains(extract_domains)
        .extract_emails(extract_emails)
        .min_domain_labels(min_labels)
        .require_word_boundaries(!no_boundaries)
        .build()
        .context("Failed to create pattern extractor")?;

    if show_stats {
        let enabled: Vec<&str> = [
            if extract_ipv4 { Some("IPv4") } else { None },
            if extract_ipv6 { Some("IPv6") } else { None },
            if extract_domains {
                Some("domains")
            } else {
                None
            },
            if extract_emails { Some("emails") } else { None },
        ]
        .iter()
        .filter_map(|&x| x)
        .collect();

        eprintln!("[INFO] Extracting: {}", enabled.join(", "));
        if extract_domains {
            eprintln!("[INFO] Min domain labels: {}", min_labels);
        }
        eprintln!("[INFO] Word boundaries: {}", !no_boundaries);
        eprintln!("[INFO] Unique mode: {}", unique);
    }

    // TODO: Support parallel processing based on threads parameter
    let _num_threads = match threads.as_deref() {
        None | Some("auto") | Some("0") => std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        Some(s) => s.parse::<usize>().with_context(|| {
            format!("Invalid thread count '{}', expected a number or 'auto'", s)
        })?,
    };

    let start_time = Instant::now();
    let mut stats = ExtractionStats::default();
    let mut seen = if unique {
        Some(FxHashSet::default())
    } else {
        None
    };

    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());

    // CSV header
    if output_format == OutputFormat::Csv {
        writeln!(writer, "type,value")?;
    }

    // Process each input file
    for input_path in &inputs {
        process_file(
            input_path,
            &extractor,
            output_format,
            &mut stats,
            &mut seen,
            &mut writer,
            show_candidates,
        )?;
    }

    writer.flush()?;

    // Print stats to stderr
    if show_stats {
        let elapsed = start_time.elapsed();
        eprintln!();
        eprintln!("[INFO] === Extraction Complete ===");
        eprintln!(
            "[INFO] Lines processed: {}",
            format_number(stats.lines_processed)
        );
        eprintln!(
            "[INFO] Patterns found: {}",
            format_number(stats.patterns_found)
        );
        if extract_ipv4 && stats.ipv4_count > 0 {
            eprintln!("[INFO]   IPv4: {}", format_number(stats.ipv4_count));
        }
        if extract_ipv6 && stats.ipv6_count > 0 {
            eprintln!("[INFO]   IPv6: {}", format_number(stats.ipv6_count));
        }
        if extract_domains && stats.domain_count > 0 {
            eprintln!("[INFO]   Domains: {}", format_number(stats.domain_count));
        }
        if extract_emails && stats.email_count > 0 {
            eprintln!("[INFO]   Emails: {}", format_number(stats.email_count));
        }
        eprintln!(
            "[INFO] Throughput: {:.2} MB/s",
            if elapsed.as_secs_f64() > 0.0 {
                (stats.bytes_processed as f64 / 1_000_000.0) / elapsed.as_secs_f64()
            } else {
                0.0
            }
        );
        eprintln!("[INFO] Total time: {:.2}s", elapsed.as_secs_f64());
    }

    Ok(())
}

fn process_file<W: Write>(
    input_path: &PathBuf,
    extractor: &Extractor,
    output_format: OutputFormat,
    stats: &mut ExtractionStats,
    seen: &mut Option<FxHashSet<String>>,
    writer: &mut W,
    show_candidates: bool,
) -> Result<()> {
    // Open input (stdin or file)
    let reader: Box<dyn BufRead> = if input_path.to_str() == Some("-") {
        Box::new(BufReader::new(io::stdin()))
    } else {
        let file = std::fs::File::open(input_path)
            .with_context(|| format!("Failed to open file: {}", input_path.display()))?;
        Box::new(BufReader::new(file))
    };

    let mut scanner = LineScanner::new(reader);
    let mut line_buf = Vec::with_capacity(4096);

    while scanner.read_line(&mut line_buf)? {
        stats.lines_processed += 1;
        stats.bytes_processed += line_buf.len();

        // Extract patterns
        for match_item in extractor.extract_from_line(&line_buf) {
            let matched_text = match_item.as_str(&line_buf);

            // Debug: show candidates if requested
            if show_candidates {
                eprintln!(
                    "[CANDIDATE] {} at {}-{}: {}",
                    match_item.item.type_name(),
                    match_item.span.0,
                    match_item.span.1,
                    matched_text
                );
            }

            // Skip if we've seen this before (unique mode)
            if let Some(ref mut seen_set) = seen {
                if !seen_set.insert(matched_text.to_string()) {
                    continue;
                }
            }

            // Output the match
            match output_format {
                OutputFormat::Json => {
                    let type_str = match_item.item.type_name().to_lowercase();
                    writeln!(
                        writer,
                        "{{\"type\":\"{}\",\"value\":\"{}\"}}",
                        type_str,
                        matched_text.replace('\\', "\\\\").replace('"', "\\\"")
                    )?;
                }
                OutputFormat::Csv => {
                    let type_str = match_item.item.type_name().to_lowercase();
                    writeln!(
                        writer,
                        "{},\"{}\"",
                        type_str,
                        matched_text.replace('"', "\"\"")
                    )?;
                }
                OutputFormat::Text => {
                    writeln!(writer, "{}", matched_text)?;
                }
            }

            // Update stats
            stats.patterns_found += 1;
            match match_item.item {
                ExtractedItem::Ipv4(_) => stats.ipv4_count += 1,
                ExtractedItem::Ipv6(_) => stats.ipv6_count += 1,
                ExtractedItem::Domain(_) => stats.domain_count += 1,
                ExtractedItem::Email(_) => stats.email_count += 1,
                ExtractedItem::Hash(_, _) => {} // Hashes don't have separate stats yet
                ExtractedItem::Bitcoin(_) => {}
                ExtractedItem::Ethereum(_) => {}
                ExtractedItem::Monero(_) => {}
            }
        }
    }

    Ok(())
}
