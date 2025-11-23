//! Parallel file processing example
//!
//! Demonstrates the `process_files_parallel` API for efficiently processing
//! multiple files across CPU cores with automatic work distribution.

use matchy::extractor::Extractor;
use matchy::{processing, Database, DatabaseBuilder, MatchMode};
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use tempfile::NamedTempFile;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Parallel File Processing Example ===\n");

    // Create a sample database
    println!("Creating sample database...");
    let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);

    let mut data = HashMap::new();
    data.insert(
        "threat_level".to_string(),
        matchy::DataValue::String("high".to_string()),
    );
    builder.add_entry("malicious.com", data.clone())?;
    builder.add_entry("evil.net", data.clone())?;
    builder.add_entry("192.168.1.100", data)?;

    let db_bytes = builder.build()?;

    // Create sample log files
    println!("Creating sample log files...");
    let mut temp_files = Vec::new();

    for i in 1..=10 {
        let mut file = NamedTempFile::new()?;
        writeln!(file, "Request from 192.168.1.{}", i)?;
        writeln!(file, "Request from 10.0.0.{}", i)?;
        if i % 3 == 0 {
            writeln!(file, "DNS query for malicious.com")?;
            writeln!(file, "Connection to evil.net")?;
        }
        writeln!(file, "Request from 192.168.1.100 - ALERT!")?;
        file.flush()?;
        temp_files.push(file);
    }

    let file_paths: Vec<_> = temp_files.iter().map(|f| f.path().to_path_buf()).collect();

    println!("\nProcessing {} files in parallel...", file_paths.len());
    println!("Worker threads: {}", rayon::current_num_threads());

    // Process files in parallel using a factory function
    // Each worker thread gets its own Worker instance
    let start = std::time::Instant::now();

    let result = processing::process_files_parallel(
        file_paths.clone(),
        None,    // Use default reader threads (num_cpus / 2)
        Some(4), // Use 4 worker threads (or None for all cores)
        move || {
            // This closure is called once per worker thread to create a Worker
            let extractor =
                Extractor::new().map_err(|e| format!("Failed to create extractor: {}", e))?;

            let db = Database::from_bytes_builder(db_bytes.clone())
                .no_cache() // Disable cache for this example
                .open()
                .map_err(|e| format!("Failed to open database: {}", e))?;

            let worker = processing::Worker::builder()
                .extractor(extractor)
                .add_database("threats", Arc::new(db))
                .build();

            Ok::<_, String>(worker)
        },
        None::<fn(&processing::WorkerStats)>,
        false, // Stop on first match (false for this example)
    )?;

    let elapsed = start.elapsed();

    // Display routing statistics
    println!("\nFile Routing:");
    println!("-------------");
    println!("Total files: {}", result.routing_stats.total_files());
    println!(
        "  → To workers (whole file): {}",
        result.routing_stats.files_to_workers
    );
    println!(
        "  → To readers (chunked): {}",
        result.routing_stats.files_to_readers
    );
    if result.routing_stats.total_bytes() > 0 {
        let bytes_to_mb = |b: u64| b as f64 / (1024.0 * 1024.0);
        println!(
            "Total size: {:.2} MB",
            bytes_to_mb(result.routing_stats.total_bytes())
        );
        println!(
            "  → Workers: {:.2} MB",
            bytes_to_mb(result.routing_stats.bytes_to_workers)
        );
        println!(
            "  → Readers: {:.2} MB",
            bytes_to_mb(result.routing_stats.bytes_to_readers)
        );
    }

    // Display worker statistics
    println!("\nWorker Statistics:");
    println!("------------------");
    println!("Lines processed: {}", result.worker_stats.lines_processed);
    println!(
        "Candidates tested: {}",
        result.worker_stats.candidates_tested
    );
    println!("Total matches: {}", result.worker_stats.matches_found);

    // Display results
    println!("\nResults:");
    println!("--------");
    println!("Match objects returned: {}", result.matches.len());
    println!("Processing time: {:?}", elapsed);
    println!("\nSample matches:");

    for (i, m) in result.matches.iter().take(5).enumerate() {
        println!(
            "  {}. {} - {} ({})",
            i + 1,
            m.source.display(),
            m.matched_text,
            m.match_type
        );
    }

    if result.matches.len() > 5 {
        println!("  ... and {} more", result.matches.len() - 5);
    }

    println!("\n=== Performance Notes ===");
    println!(
        "- Used {} worker threads and {} file paths",
        4,
        file_paths.len()
    );
    println!("- Small files (<100MB) are processed whole (minimal overhead)");
    println!("- Large files (>100MB) are only chunked when needed for parallelism");
    println!("- Reader threads handle I/O and chunking for large files in parallel");
    println!("- Each worker has its own Worker instance with statistics tracking");

    Ok(())
}
