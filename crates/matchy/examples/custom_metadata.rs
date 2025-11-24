//! Example: Building a database with custom metadata
//!
//! Shows how to set custom database_type and description fields

use matchy::data_section::DataValue;
use matchy::mmdb_builder::MmdbBuilder;
use matchy::MatchMode;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Building database with custom metadata...\n");

    // Create builder with custom metadata
    let mut builder = MmdbBuilder::new(MatchMode::CaseSensitive)
        .with_database_type("MyCompany-ThreatIntel")
        .with_description("en", "Corporate threat intelligence database")
        .with_description(
            "es",
            "Base de datos de inteligencia de amenazas corporativa",
        )
        .with_description("fr", "Base de données de renseignements sur les menaces");

    // Add some threat data
    let mut malicious_ip = HashMap::new();
    malicious_ip.insert(
        "threat_level".to_string(),
        DataValue::String("critical".to_string()),
    );
    malicious_ip.insert(
        "category".to_string(),
        DataValue::String("botnet".to_string()),
    );
    malicious_ip.insert(
        "first_seen".to_string(),
        DataValue::String("2024-01-15".to_string()),
    );
    builder.add_entry("198.51.100.0/24", malicious_ip)?;

    let mut suspicious_pattern = HashMap::new();
    suspicious_pattern.insert(
        "threat_level".to_string(),
        DataValue::String("medium".to_string()),
    );
    suspicious_pattern.insert(
        "category".to_string(),
        DataValue::String("phishing".to_string()),
    );
    builder.add_entry("*.phishing-site.com", suspicious_pattern)?;

    let mut tracking_pattern = HashMap::new();
    tracking_pattern.insert(
        "threat_level".to_string(),
        DataValue::String("low".to_string()),
    );
    tracking_pattern.insert(
        "category".to_string(),
        DataValue::String("tracker".to_string()),
    );
    builder.add_entry("*tracker*.example.com", tracking_pattern)?;

    // Build and save
    println!("Building database...");
    let database_bytes = builder.build()?;

    let output_file = "custom_metadata.mmdb";
    std::fs::write(output_file, &database_bytes)?;

    println!("✓ Database created: {}", output_file);
    println!("  Size: {} bytes", database_bytes.len());
    println!("\nMetadata:");
    println!("  Database Type: MyCompany-ThreatIntel");
    println!("  Descriptions:");
    println!("    [en] Corporate threat intelligence database");
    println!("    [es] Base de datos de inteligencia de amenazas corporativa");
    println!("    [fr] Base de données de renseignements sur les menaces");

    println!("\nYou can query it with:");
    println!("  paraglob query {} 198.51.100.50 --data", output_file);
    println!(
        "  paraglob query {} malware.phishing-site.com --data",
        output_file
    );
    println!("  mmdblookup --file {} --ip 198.51.100.50", output_file);

    Ok(())
}
