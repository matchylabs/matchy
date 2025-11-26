//! Example: Building an IP address database with DatabaseBuilder
//!
//! Demonstrates how to build a database with IP addresses and CIDR ranges.

use matchy::mmdb_builder::DatabaseBuilder;
use matchy::DataValue;
use matchy::MatchMode;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Building IP address database...\n");

    // Create a builder
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    // Add some IP addresses with associated data
    println!("Adding IP entries:");

    // 1. Private network ranges
    let mut data1 = HashMap::new();
    data1.insert(
        "network".to_string(),
        DataValue::String("Private Network".to_string()),
    );
    data1.insert("type".to_string(), DataValue::String("RFC1918".to_string()));
    builder.add_entry("192.168.0.0/16", data1.clone())?;
    println!("  Added: 192.168.0.0/16 - Private Network (RFC1918)");

    let mut data2 = HashMap::new();
    data2.insert(
        "network".to_string(),
        DataValue::String("Private Network".to_string()),
    );
    data2.insert("type".to_string(), DataValue::String("RFC1918".to_string()));
    builder.add_entry("10.0.0.0/8", data2.clone())?;
    println!("  Added: 10.0.0.0/8 - Private Network (RFC1918)");

    // 2. Public DNS servers
    let mut data3 = HashMap::new();
    data3.insert(
        "service".to_string(),
        DataValue::String("Google DNS".to_string()),
    );
    data3.insert(
        "provider".to_string(),
        DataValue::String("Google".to_string()),
    );
    builder.add_entry("8.8.8.8", data3)?;
    println!("  Added: 8.8.8.8 - Google DNS");

    let mut data4 = HashMap::new();
    data4.insert(
        "service".to_string(),
        DataValue::String("Cloudflare DNS".to_string()),
    );
    data4.insert(
        "provider".to_string(),
        DataValue::String("Cloudflare".to_string()),
    );
    builder.add_entry("1.1.1.1", data4)?;
    println!("  Added: 1.1.1.1 - Cloudflare DNS");

    // 3. IPv6 address
    let mut data5 = HashMap::new();
    data5.insert(
        "service".to_string(),
        DataValue::String("Google DNS IPv6".to_string()),
    );
    data5.insert(
        "provider".to_string(),
        DataValue::String("Google".to_string()),
    );
    builder.add_entry("2001:4860:4860::8888", data5)?;
    println!("  Added: 2001:4860:4860::8888 - Google DNS IPv6");

    // Get statistics
    let stats = builder.stats();
    println!("\nDatabase statistics:");
    println!("  Total entries: {}", stats.total_entries);
    println!("  IP entries: {}", stats.ip_entries);
    println!("  Literal entries: {}", stats.literal_entries);
    println!("  Glob entries: {}", stats.glob_entries);

    // Build the database
    println!("\nBuilding database...");
    let database_bytes = builder.build()?;
    println!("✓ Database built successfully!");
    println!("  Size: {} bytes", database_bytes.len());

    // Could save to disk
    // std::fs::write("ip_database.mmdb", &database_bytes)?;
    // println!("✓ Database saved to ip_database.mmdb");

    println!("\n✓ Success! The IP tree has been built and serialized.");
    println!(
        "  The database contains {} IP entries in MMDB format.",
        stats.ip_entries
    );

    Ok(())
}
