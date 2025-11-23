//! Demonstration of the lookup_extracted API
//!
//! This example shows how to use the efficient `lookup_extracted()` method
//! instead of manually matching on ExtractedItem variants. This pattern is
//! ideal for integrations like Vector where you extract-then-lookup in a loop.
//!
//! Run with:
//!   cargo run --example lookup_extracted_demo

use matchy::data_section::DataValue;
use matchy::extractor::Extractor;
use matchy::{Database, DatabaseBuilder, MatchMode};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build a small test database with IPs and domains
    println!("Building test database...");
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    // Helper to create single-field data
    let make_data = |threat: &str| {
        let mut data = HashMap::new();
        data.insert("threat".to_string(), DataValue::String(threat.to_string()));
        data
    };

    // Add some threat IPs
    builder.add_ip("192.168.1.100/32", make_data("Known botnet C2"))?;
    builder.add_ip("10.0.0.50/32", make_data("Malware distribution"))?;

    // Add some threat domains
    builder.add_entry("evil.com", make_data("Phishing site"))?;
    builder.add_entry("malware.example.com", make_data("Malware host"))?;

    // Build database in memory
    let db_bytes = builder.build()?;
    let db = Database::from_bytes_builder(db_bytes).open()?;

    // Create extractor
    let extractor = Extractor::new()?;

    // Sample log lines to analyze
    let log_lines = [
        b"Connection from 192.168.1.100 detected" as &[u8],
        b"DNS query for evil.com from client",
        b"Normal traffic from 8.8.8.8",
        b"Request to malware.example.com blocked",
        b"User visited google.com successfully",
    ];

    println!("\nAnalyzing log lines for threats:\n");

    for (idx, log_line) in log_lines.iter().enumerate() {
        println!("Line {}: {}", idx + 1, String::from_utf8_lossy(log_line));

        let mut found_threat = false;

        // Extract all candidates from the line
        for item in extractor.extract_from_line(log_line) {
            // Use lookup_extracted - no match statement needed!
            // This automatically uses the optimal lookup path:
            // - IP addresses -> lookup_ip() (typed, no string conversion)
            // - Everything else -> lookup() (string-based)
            if let Some(result) = db.lookup_extracted(&item, log_line)? {
                // Skip NotFound results
                if matches!(result, matchy::QueryResult::NotFound) {
                    continue;
                }

                found_threat = true;
                let matched_text = item.as_str(log_line);
                let match_type = item.item.type_name();

                print!("  ⚠️  THREAT: {} ({})", matched_text, match_type);

                // Extract threat intel data
                match result {
                    matchy::QueryResult::Ip {
                        data: DataValue::Map(map),
                        ..
                    } => {
                        if let Some(DataValue::String(desc)) = map.get("threat") {
                            print!(" - {}", desc);
                        }
                    }
                    matchy::QueryResult::Pattern { data, .. } => {
                        for d in data.iter().flatten() {
                            if let DataValue::Map(map) = d {
                                if let Some(DataValue::String(desc)) = map.get("threat") {
                                    print!(" - {}", desc);
                                }
                            }
                        }
                    }
                    _ => {}
                }
                println!();
            }
        }

        if !found_threat {
            println!("  ✓ Clean (no threats detected)");
        }
        println!();
    }

    // Show statistics
    let stats = db.stats();
    println!("Database Statistics:");
    println!("  Total queries: {}", stats.total_queries);
    println!("  Matches found: {}", stats.queries_with_match);
    println!("  IP queries: {}", stats.ip_queries);
    println!("  String queries: {}", stats.string_queries);
    println!("  Cache hit rate: {:.1}%", stats.cache_hit_rate() * 100.0);

    Ok(())
}
