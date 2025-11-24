//! Endianness Handling Demonstration
//!
//! This example shows how matchy handles endianness for cross-platform
//! zero-copy database loading.
//!
//! # Design
//!
//! - Databases are stored in little-endian format (x86/ARM standard)
//! - Header includes endianness marker for detection
//! - On big-endian systems, values are byte-swapped transparently on read
//! - Zero-copy still works - no buffer rewriting needed
//!
//! # Performance
//!
//! - Little-endian (x86/ARM): Zero overhead, compiles to direct loads
//! - Big-endian (POWER/SPARC): Single CPU instruction per read (bswap)

use matchy::{DataValue, Database, DatabaseBuilder, MatchMode};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Matchy Endianness Support Demo ===\n");

    // Detect native endianness
    #[cfg(target_endian = "little")]
    println!("Running on: Little-endian system (x86/ARM)");

    #[cfg(target_endian = "big")]
    println!("Running on: Big-endian system (POWER/SPARC)");

    // Build a small database
    println!("\n1. Building database...");
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    // Add some test patterns
    let mut data = HashMap::new();
    data.insert(
        "category".to_string(),
        DataValue::String("test".to_string()),
    );
    builder.add_entry("*.example.com", data.clone())?;
    builder.add_entry("test_*", data)?;

    let db_bytes = builder.build()?;
    println!("   Database size: {} bytes", db_bytes.len());

    // Check database format
    println!("\n2. Database format info:");
    println!("   Database size: {} bytes", db_bytes.len());
    println!("   Format: Hybrid MMDB + Pattern matcher");
    println!("   All multi-byte values stored in little-endian format");
    println!("   Endianness marker: Always written as 0x01 (little-endian)");

    #[cfg(target_endian = "little")]
    println!("   Native system: Little-endian (no byte swapping needed)");

    #[cfg(target_endian = "big")]
    println!("   Native system: Big-endian (transparent byte swapping on read)");

    // Write to temp file and load back
    println!("\n3. Testing zero-copy loading...");
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join("matchy_endian_test.mxy");
    std::fs::write(&db_path, &db_bytes)?;

    // Load with mmap (zero-copy)
    let db = Database::from(db_path.to_str().unwrap()).open()?;
    println!("   ✓ Database loaded (zero-copy mmap)");

    // Test queries
    println!("\n4. Testing queries...");

    if let Some(result) = db.lookup("test.example.com")? {
        println!("   ✓ Match found: test.example.com -> {:?}", result);
    }

    if let Some(result) = db.lookup("test_file.txt")? {
        println!("   ✓ Match found: test_file.txt -> {:?}", result);
    }

    // Performance note
    println!("\n5. Performance characteristics:");
    println!("   - Database format: Always little-endian");
    println!("   - Storage: Zero-copy memory mapped file");

    #[cfg(target_endian = "little")]
    {
        println!("   - Read overhead: Zero (native endianness)");
        println!("   - Instructions: Direct memory load");
    }

    #[cfg(target_endian = "big")]
    {
        println!("   - Read overhead: Single CPU instruction per value");
        println!("   - Instructions: Load + byte swap (bswap)");
    }

    println!("   - No buffer rewriting needed!");
    println!("   - Instant loading (~1ms regardless of size)");

    // Cleanup
    std::fs::remove_file(&db_path).ok();

    println!("\n=== Demo Complete ===");
    Ok(())
}
