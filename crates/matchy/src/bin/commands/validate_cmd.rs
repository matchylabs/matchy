use anyhow::{Context, Result};
use matchy::validation::{validate_database, ValidationLevel};
use serde_json::json;
use std::path::PathBuf;
use std::time::Instant;

pub fn cmd_validate(
    database: PathBuf,
    level_str: String,
    json_output: bool,
    verbose: bool,
) -> Result<()> {
    // Parse validation level
    let level = match level_str.to_lowercase().as_str() {
        "standard" => ValidationLevel::Standard,
        "strict" => ValidationLevel::Strict,
        _ => {
            anyhow::bail!(
                "Invalid validation level: '{}'. Must be: standard or strict",
                level_str
            );
        }
    };

    // Validate the database
    let start = Instant::now();
    let report = validate_database(&database, level)
        .with_context(|| format!("Validation failed: {}", database.display()))?;
    let duration = start.elapsed();

    // Output results
    if json_output {
        let output = json!({
            "database": database.display().to_string(),
            "validation_level": level_str,
            "is_valid": report.is_valid(),
            "duration_ms": duration.as_millis(),
            "errors": report.errors,
            "warnings": report.warnings,
            "info": report.info,
            "stats": {
                "file_size": report.stats.file_size,
                "version": report.stats.version,
                "database_type": report.stats.database_type,
                "ac_node_count": report.stats.ac_node_count,
                "pattern_count": report.stats.pattern_count,
                "ip_entry_count": report.stats.ip_entry_count,
                "literal_count": report.stats.literal_count,
                "glob_count": report.stats.glob_count,
                "has_data_section": report.stats.has_data_section,
                "has_ac_literal_mapping": report.stats.has_ac_literal_mapping,
                "schema_validated": report.stats.schema_validated,
                "schema_entries_checked": report.stats.schema_entries_checked,
                "schema_validation_failures": report.stats.schema_validation_failures,
            }
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        // Human-readable output
        println!("Validating: {}", database.display());
        println!("Level:      {}", level_str);
        println!();

        // Statistics
        println!("Statistics:");
        println!("  {}", report.stats.summary());
        println!("  Validation time: {:.2}ms", duration.as_millis());
        println!();

        // Errors
        if !report.errors.is_empty() {
            println!("❌ ERRORS ({}):", report.errors.len());
            for error in &report.errors {
                println!("  • {}", error);
            }
            println!();
        }

        // Warnings
        if !report.warnings.is_empty() && verbose {
            println!("⚠️  WARNINGS ({}):", report.warnings.len());
            for warning in &report.warnings {
                println!("  • {}", warning);
            }
            println!();
        } else if !report.warnings.is_empty() {
            println!(
                "⚠️  {} warning(s) (use --verbose to show)",
                report.warnings.len()
            );
            println!();
        }

        // Info messages
        if verbose && !report.info.is_empty() {
            println!("ℹ️  INFORMATION ({}):", report.info.len());
            for info in &report.info {
                println!("  • {}", info);
            }
            println!();
        }

        // Final verdict
        if report.is_valid() {
            println!("✅ VALIDATION PASSED");
            println!("   Database is safe to use.");
        } else {
            println!("❌ VALIDATION FAILED");
            println!("   Database has {} critical error(s).", report.errors.len());
            println!("   DO NOT use this database without fixing the errors.");
        }
    }

    // Exit with appropriate code
    if report.is_valid() {
        Ok(())
    } else {
        std::process::exit(1);
    }
}
