//! Example demonstrating the prefix convention for explicit type control
//!
//! This example shows how to use `literal:`, `glob:`, and `ip:` prefixes to
//! override auto-detection and explicitly control how entries are classified.

use matchy::{DataValue, Database, DatabaseBuilder, MatchMode};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Prefix Convention Example ===\n");

    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    // Auto-detection examples
    println!("1. Auto-Detection (default behavior):");

    let mut data = HashMap::new();
    data.insert(
        "type".to_string(),
        DataValue::String("auto-detected".to_string()),
    );

    builder.add_entry("8.8.8.8", data.clone())?;
    println!("   '8.8.8.8' → Detected as IP address");

    builder.add_entry("*.example.com", data.clone())?;
    println!("   '*.example.com' → Detected as glob pattern (has wildcard)");

    builder.add_entry("evil.com", data.clone())?;
    println!("   'evil.com' → Detected as literal string (no wildcards)");

    // Force literal matching
    println!("\n2. Force Literal Matching with 'literal:' prefix:");

    let mut literal_data = HashMap::new();
    literal_data.insert(
        "note".to_string(),
        DataValue::String("forced literal".to_string()),
    );

    // This domain literally contains an asterisk character
    builder.add_entry("literal:*.actually-in-domain.com", literal_data.clone())?;
    println!("   'literal:*.actually-in-domain.com' → Forced to literal");
    println!("      (domain literally contains '*' character)");

    // Force literal for a string with brackets
    builder.add_entry("literal:file[1].txt", literal_data.clone())?;
    println!("   'literal:file[1].txt' → Forced to literal");
    println!("      (brackets are literal, not glob character class)");

    // Force glob matching
    println!("\n3. Force Glob Matching with 'glob:' prefix:");

    let mut glob_data = HashMap::new();
    glob_data.insert(
        "note".to_string(),
        DataValue::String("forced glob".to_string()),
    );

    // Force a string without wildcards to be treated as a glob pattern
    builder.add_entry("glob:test.com", glob_data.clone())?;
    println!("   'glob:test.com' → Forced to glob pattern");
    println!("      (no wildcards, but explicitly marked as glob)");

    // Force IP parsing
    println!("\n4. Force IP Parsing with 'ip:' prefix:");

    let mut ip_data = HashMap::new();
    ip_data.insert(
        "note".to_string(),
        DataValue::String("forced IP".to_string()),
    );

    builder.add_entry("ip:10.0.0.0/8", ip_data)?;
    println!("   'ip:10.0.0.0/8' → Forced to IP (rarely needed)");

    // Build the database
    println!("\n5. Building database...");
    let db_bytes = builder.build()?;

    // Write to temporary file
    let tmp_path = std::env::temp_dir().join("prefix_convention_test.mxy");
    std::fs::write(&tmp_path, &db_bytes)?;
    println!("   Database written to: {}", tmp_path.display());

    // Query examples
    println!("\n6. Querying the database:");
    let db = Database::from(tmp_path.to_str().unwrap()).open()?;

    // Query IP
    if let Some(result) = db.lookup("8.8.8.8")? {
        println!("   ✓ Found IP: 8.8.8.8");
        println!("     {:?}", result);
    }

    // Query glob pattern
    if let Some(result) = db.lookup("subdomain.example.com")? {
        println!("   ✓ Matched pattern: *.example.com");
        println!("     {:?}", result);
    }

    // Query literal (exact match only)
    if let Some(result) = db.lookup("evil.com")? {
        println!("   ✓ Found literal: evil.com");
        println!("     {:?}", result);
    }

    // This won't match because "*.actually-in-domain.com" is stored as literal
    if db.lookup("subdomain.actually-in-domain.com")?.is_none() {
        println!("   ✗ No match for 'subdomain.actually-in-domain.com'");
        println!("     (*.actually-in-domain.com is stored as literal, not glob)");
    }

    // But exact match will work
    if let Some(result) = db.lookup("*.actually-in-domain.com")? {
        println!("   ✓ Found literal: *.actually-in-domain.com");
        println!("     {:?}", result);
    }

    // Cleanup
    std::fs::remove_file(&tmp_path)?;

    println!("\n=== Summary ===");
    println!("Use prefixes when:");
    println!("  • literal: - Domain/string contains glob-like chars (*, ?, [, ])");
    println!("  • glob:    - Force glob matching without wildcards (testing)");
    println!("  • ip:      - Explicit IP parsing (rarely needed)");
    println!("\nWithout prefix, auto-detection works for 99% of use cases!");

    Ok(())
}
