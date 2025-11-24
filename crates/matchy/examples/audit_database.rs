//! Audit Database Safety Example
//!
//! This example demonstrates the Audit validation mode which tracks all unsafe code
//! usage and trust assumptions in the matchy codebase. Use this to understand:
//!
//! - Where unsafe operations occur in the codebase
//! - What validation is bypassed in --trusted mode
//! - Security risks of using untrusted databases
//! - How to safely validate databases before loading
//!
//! Usage:
//!   cargo run --example audit_database -- <path-to-database.mxy>

use matchy::validation::{validate_database, ValidationLevel};
use std::env;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <database.mxy>", args[0]);
        eprintln!();
        eprintln!("Example:");
        eprintln!("  cargo run --example audit_database -- tests/data/test.mxy");
        std::process::exit(1);
    }

    let db_path = Path::new(&args[1]);

    if !db_path.exists() {
        eprintln!("Error: File not found: {}", db_path.display());
        std::process::exit(1);
    }

    println!("═══════════════════════════════════════════════════════════════");
    println!("   MATCHY DATABASE SAFETY AUDIT");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    println!("Database: {}", db_path.display());
    println!();

    // Run audit-level validation
    println!("Running audit validation...");
    println!();

    let report = validate_database(db_path, ValidationLevel::Audit)?;

    // Print basic stats
    println!("📊 DATABASE STATISTICS");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("{}", report.stats.summary());
    println!();

    // Print validation status
    if report.is_valid() {
        println!("✅ DATABASE STRUCTURE: VALID");
    } else {
        println!("❌ DATABASE STRUCTURE: INVALID");
    }
    println!();

    // Print errors
    if !report.errors.is_empty() {
        println!("🚨 ERRORS ({})", report.errors.len());
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        for error in &report.errors {
            println!("  ❌ {}", error);
        }
        println!();
    }

    // Print warnings
    if !report.warnings.is_empty() {
        println!("⚠️  WARNINGS ({})", report.warnings.len());
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        for warning in &report.warnings {
            println!("  ⚠️  {}", warning);
        }
        println!();
    }

    // Print unsafe code locations
    if !report.stats.unsafe_code_locations.is_empty() {
        println!(
            "🔧 UNSAFE CODE AUDIT ({} locations)",
            report.stats.unsafe_code_locations.len()
        );
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        for (i, loc) in report.stats.unsafe_code_locations.iter().enumerate() {
            println!("  {}. {}", i + 1, loc.location);
            println!("     Operation: {:?}", loc.operation);
            println!("     Justification: {}", loc.justification);
            println!();
        }
    }

    // Print trust assumptions
    if !report.stats.trust_assumptions.is_empty() {
        println!(
            "🔒 TRUST MODE ANALYSIS ({} assumptions)",
            report.stats.trust_assumptions.len()
        );
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        for (i, assumption) in report.stats.trust_assumptions.iter().enumerate() {
            println!("  {}. Context: {}", i + 1, assumption.context);
            println!("     Bypassed Check: {}", assumption.bypassed_check);
            println!("     ⚠️  Risk: {}", assumption.risk);
            println!();
        }
    }

    // Print recommendations
    println!("📝 RECOMMENDATIONS");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    if report.is_valid() {
        println!("  ✅ Database structure is valid");
        println!("  ✅ Safe to load in normal mode (without --trusted)");
        println!();
        println!("  ⚡ For trusted databases from known sources:");
        println!("     - Use --trusted flag for 15-20% faster loading");
        println!("     - Skips UTF-8 validation (assumes pre-validated)");
        println!("     - Only safe if database source is fully trusted");
    } else {
        println!("  ❌ DO NOT load this database!");
        println!("  ❌ Validation errors indicate corruption or malicious content");
        println!("  ❌ Loading could cause crashes or undefined behavior");
    }
    println!();

    // Summary
    println!("═══════════════════════════════════════════════════════════════");
    println!("   AUDIT COMPLETE");
    println!("═══════════════════════════════════════════════════════════════");
    println!();

    if !report.is_valid() {
        std::process::exit(1);
    }

    Ok(())
}
