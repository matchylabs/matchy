//! Example: Building a threat intelligence database from MISP JSON files
//!
//! This example demonstrates how to:
//! 1. Load MISP JSON threat intelligence feeds
//! 2. Extract indicators (IPs, domains, hashes, etc.)
//! 3. Build a searchable database with all metadata preserved
//! 4. Query the database to check for threats
//!
//! Usage:
//!   cargo run --example build_misp_database -- misp-example.json
//!   cargo run --example build_misp_database -- file1.json file2.json file3.json

use matchy::data_section::DataValue;
use matchy::database::Database;
use matchy::misp_importer::MispImporter;
use matchy::MatchMode;
use std::env;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <misp-json-file> [additional-files...]", args[0]);
        eprintln!("\nExample:");
        eprintln!("  {} misp-example.json", args[0]);
        eprintln!("  {} threats1.json threats2.json", args[0]);
        std::process::exit(1);
    }

    let json_files = &args[1..];

    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║      MISP Threat Intelligence Database Builder                ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    // Load MISP JSON files
    println!("📁 Loading MISP JSON files:");
    for file in json_files {
        println!("   • {}", file);
    }
    println!();

    let importer = MispImporter::from_files(json_files)?;

    // Show import statistics
    let stats = importer.stats();
    println!("📊 Import Statistics:");
    println!("   Events imported:     {}", stats.total_events);
    println!("   Total attributes:    {}", stats.total_attributes);
    println!("   Objects processed:   {}", stats.total_objects);
    println!();

    // Build the database
    println!("🔨 Building threat intelligence database...");
    let builder = importer.build_database(MatchMode::CaseSensitive)?;

    let builder_stats = builder.stats();
    println!("   ✓ Total indicators:  {}", builder_stats.total_entries);
    println!("   ✓ IP entries:        {}", builder_stats.ip_entries);
    println!("   ✓ Literal entries:   {}", builder_stats.literal_entries);
    println!("   ✓ Glob entries:      {}", builder_stats.glob_entries);
    println!();

    // Build database bytes
    println!("💾 Serializing database...");
    let database_bytes = builder.build()?;
    println!(
        "   ✓ Database size: {} bytes ({:.2} MB)",
        database_bytes.len(),
        database_bytes.len() as f64 / (1024.0 * 1024.0)
    );
    println!();

    // Save to file
    let output_file = "misp_threat_intel.mmdb";
    fs::write(output_file, &database_bytes)?;
    println!("✅ Database saved to: {}\n", output_file);

    // Demonstrate database usage
    println!("🔍 Testing database queries...\n");

    // Try to load the database we just created
    let db_result = Database::from_bytes(database_bytes);

    if let Err(e) = &db_result {
        println!("   ℹ️  Note: Pattern-only databases require direct Paraglob loading");
        println!("   (This is normal when there are no IP addresses in the data)");
        println!("   Error: {:?}\n", e);

        println!("╔════════════════════════════════════════════════════════════════╗");
        println!("║  Database built successfully!                                  ║");
        println!("║                                                                ║");
        println!(
            "║  The database contains {} threat indicators.            ║",
            builder_stats.literal_entries + builder_stats.glob_entries
        );
        println!("║  Load it using Paraglob API for pattern matching.             ║");
        println!("╚════════════════════════════════════════════════════════════════╝");
        return Ok(());
    }

    let db = db_result?;

    // Example queries based on the sample data
    let test_queries = vec![
        ("7789611e7c2a7e78d0bded05924ede23", "MD5 hash from sample"),
        ("192.168.1.100", "IP address check"),
        ("evil.com", "Domain check"),
    ];

    for (query, description) in test_queries {
        print!("   Query: {} ({})", query, description);

        match db.lookup(query)? {
            Some(result) => match result {
                matchy::database::QueryResult::Ip { data, .. } => {
                    println!(" ✓ MATCH FOUND (IP)");
                    if let DataValue::Map(map) = &data {
                        println!("      Type: {:?}", map.get("type"));
                        println!("      Event: {:?}", map.get("event_info"));
                        if let Some(tags) = map.get("tags") {
                            println!("      Tags: {:?}", tags);
                        }
                        if let Some(threat) = map.get("threat_level") {
                            println!("      Threat Level: {:?}", threat);
                        }
                    }
                }
                matchy::database::QueryResult::Pattern { data, .. } => {
                    println!(" ✓ MATCH FOUND (Pattern)");
                    if let Some(Some(DataValue::Map(map))) = data.first() {
                        println!("      Type: {:?}", map.get("type"));
                        println!("      Event: {:?}", map.get("event_info"));
                        if let Some(tags) = map.get("tags") {
                            println!("      Tags: {:?}", tags);
                        }
                        if let Some(threat) = map.get("threat_level") {
                            println!("      Threat Level: {:?}", threat);
                        }
                    }
                }
                matchy::database::QueryResult::NotFound => {
                    println!(" ✗ No match");
                }
            },
            None => {
                println!(" ✗ No match");
            }
        }
        println!();
    }

    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║  Database ready for use!                                      ║");
    println!("║                                                                ║");
    println!("║  You can now:                                                  ║");
    println!("║  • Load it in your application with Database::from_file()     ║");
    println!("║  • Query IPs, hashes, domains, and more                       ║");
    println!("║  • Access all metadata (tags, threat levels, etc.)            ║");
    println!("╚════════════════════════════════════════════════════════════════╝");

    Ok(())
}
