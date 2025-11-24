use anyhow::{Context, Result};
use matchy::{mmdb_builder::MmdbBuilder, DataValue, MatchMode};
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead};
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::cli_utils::json_to_data_map;

/// Set file permissions to read-only (0444 on Unix, read-only attribute on Windows)
fn set_readonly(path: &PathBuf) -> Result<()> {
    let mut perms = fs::metadata(path)
        .with_context(|| format!("Failed to get metadata for: {}", path.display()))?
        .permissions();

    #[cfg(unix)]
    {
        perms.set_mode(0o444); // r--r--r--
    }

    #[cfg(not(unix))]
    {
        // On Windows and other platforms, use the cross-platform read-only API
        perms.set_readonly(true);
    }

    fs::set_permissions(path, perms)
        .with_context(|| format!("Failed to set read-only permissions: {}", path.display()))?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_build(
    inputs: Vec<PathBuf>,
    output: PathBuf,
    format: String,
    database_type: Option<String>,
    description: Option<String>,
    desc_lang: String,
    verbose: bool,
    debug: bool,
    case_insensitive: bool,
) -> Result<()> {
    let match_mode = if case_insensitive {
        MatchMode::CaseInsensitive
    } else {
        MatchMode::CaseSensitive
    };

    if debug {
        println!("Building unified MMDB database (IP + patterns)...");
        println!("  Input files: {}", inputs.len());
        for input in &inputs {
            println!("    - {}", input.display());
        }
        println!("  Output: {}", output.display());
        println!("  Format: {}", format);
        println!(
            "  Match mode: {}",
            if case_insensitive {
                "case-insensitive"
            } else {
                "case-sensitive"
            }
        );
        println!();
    }

    let mut builder = MmdbBuilder::new(match_mode);

    // Apply metadata if provided
    if let Some(db_type) = database_type {
        builder = builder.with_database_type(db_type);
    }

    if let Some(desc) = description {
        builder = builder.with_description(desc_lang, desc);
    }

    match format.as_str() {
        "text" => {
            // Read entries from text file(s) (one per line)
            // Auto-detects IP addresses/CIDRs vs patterns
            let mut total_count = 0;

            for input in &inputs {
                if debug && inputs.len() > 1 {
                    println!("  Reading: {}...", input.display());
                }

                // Validate that the file doesn't look like JSON or CSV
                // (common user error: using wrong format flag)
                if let Ok(content) = fs::read_to_string(input) {
                    let trimmed = content.trim_start();
                    if trimmed.starts_with('{') || trimmed.starts_with('[') {
                        if trimmed.contains("\"Event\"") {
                            anyhow::bail!(
                                "File {} appears to be MISP JSON format.\n\n\
                                You specified --format text, but this looks like MISP JSON.\n\
                                Try: --format misp (or -f misp)",
                                input.display()
                            );
                        } else {
                            eprintln!(
                                "Warning: {} looks like JSON but you specified --format text.\n\
                                If this is a JSON file, use --format json instead.",
                                input.display()
                            );
                        }
                    }
                    // Check for CSV-like content
                    let first_line = content.lines().next().unwrap_or("");
                    if first_line.contains(',') && first_line.split(',').count() > 3 {
                        eprintln!(
                            "Warning: {} looks like CSV but you specified --format text.\n\
                            If this is a CSV file, use --format csv instead.",
                            input.display()
                        );
                    }
                }

                let file = fs::File::open(input)
                    .with_context(|| format!("Failed to open input file: {}", input.display()))?;
                let reader = io::BufReader::new(file);

                let mut count = 0;
                for line in reader.lines() {
                    let line = line?;
                    let entry = line.trim();
                    if !entry.is_empty() && !entry.starts_with('#') {
                        // Auto-detection: builder will determine if it's IP or pattern
                        builder.add_entry(entry, HashMap::new())?;
                        count += 1;
                        total_count += 1;
                        if debug && total_count % 1000 == 0 {
                            println!("    Added {} entries...", total_count);
                        }
                    }
                }

                if debug && inputs.len() > 1 {
                    println!("    {} entries from this file", count);
                }
            }

            if debug {
                println!("  Total: {} entries", total_count);
            }
        }
        "csv" => {
            // Read entries with data from CSV file(s)
            // First column must be named "entry" (or "key") containing IP/CIDR/pattern
            // Remaining columns become metadata fields
            let mut total_entries = 0;

            for input in &inputs {
                if debug && inputs.len() > 1 {
                    println!("  Reading: {}...", input.display());
                }

                let file = fs::File::open(input)
                    .with_context(|| format!("Failed to open CSV file: {}", input.display()))?;
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

                    if debug && total_entries % 1000 == 0 {
                        println!("    Added {} entries...", total_entries);
                    }
                }

                if debug && inputs.len() > 1 {
                    println!("    {} entries from this file", reader.position().line());
                }
            }

            if debug {
                println!("  Total: {} entries", total_entries);
            }
        }
        "json" => {
            // Read entries with data from JSON file(s)
            // Format: [{"key": "192.168.0.0/16" or "*.example.com", "data": {...}}]
            let mut total_entries = 0;

            for input in &inputs {
                if debug && inputs.len() > 1 {
                    println!("  Reading: {}...", input.display());
                }

                let content = fs::read_to_string(input)
                    .with_context(|| format!("Failed to read JSON file: {}", input.display()))?;
                let entries: Vec<serde_json::Value> =
                    serde_json::from_str(&content).context("Failed to parse JSON")?;

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

                    if debug && total_entries % 1000 == 0 {
                        println!("    Added {} entries...", total_entries);
                    }
                }

                if debug && inputs.len() > 1 {
                    println!("    {} entries from this file", entries.len());
                }
            }

            if debug {
                println!("  Total: {} entries", total_entries);
            }
        }
        "misp" => {
            // Read MISP JSON threat intelligence file(s) with streaming (low memory)
            use matchy::misp_importer::MispImporter;

            if debug {
                println!("  Processing MISP JSON files (streaming mode)...");
            }

            // Convert Vec<PathBuf> to Vec<&Path> for build_from_files
            let input_refs: Vec<&PathBuf> = inputs.iter().collect();

            // Use streaming import to process one file at a time
            // This keeps memory usage low even for very large datasets
            builder = MispImporter::build_from_files(
                &input_refs,
                MatchMode::CaseSensitive,
                false, // Use full metadata
            )
            .context("Failed to process MISP JSON files")?;

            if debug {
                let stats = builder.stats();
                println!("  Total indicators: {}", stats.total_entries);
            }
        }
        _ => {
            anyhow::bail!(
                "Unknown format: {}. Use 'text', 'csv', 'json', or 'misp'",
                format
            );
        }
    }

    // Always show statistics
    let stats = builder.stats();
    if verbose || debug {
        println!("\nBuilding database:");
        println!("  Total entries:   {}", stats.total_entries);
        println!("  IP entries:      {}", stats.ip_entries);
        println!("  Literal entries: {}", stats.literal_entries);
        println!("  Glob entries:    {}", stats.glob_entries);
    }

    if debug {
        println!("\nSerializing...");
    }

    let database_bytes = builder.build().context("Failed to build database")?;

    if debug {
        println!("Writing to disk...");
    }

    fs::write(&output, &database_bytes)
        .with_context(|| format!("Failed to save database: {}", output.display()))?;

    // Set file to read-only to protect mmap integrity
    set_readonly(&output).with_context(|| {
        format!(
            "Failed to set read-only permissions on: {}",
            output.display()
        )
    })?;

    // Always show success message (always displayed)
    if verbose || debug {
        println!("\n✓ Database built successfully!");
        println!("  Output:        {}", output.display());
        println!(
            "  Database size: {:.2} MB ({} bytes)",
            database_bytes.len() as f64 / (1024.0 * 1024.0),
            database_bytes.len()
        );
    } else {
        println!("✓ Database built: {}", output.display());
    }

    if debug {
        println!("  Format:        MMDB (extended with patterns)");
    }

    Ok(())
}
