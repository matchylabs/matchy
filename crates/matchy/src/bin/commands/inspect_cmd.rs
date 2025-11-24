use anyhow::{Context, Result};
use matchy::{DataValue, Database};
use serde_json::json;
use std::path::PathBuf;

use crate::cli_utils::{
    data_value_to_json, extract_uint_from_datavalue, format_data_value, format_unix_timestamp,
};

pub fn cmd_inspect(database: PathBuf, json_output: bool, verbose: bool) -> Result<()> {
    // Load database using fluent API
    let db = Database::from(database.to_str().unwrap())
        .open()
        .with_context(|| format!("Failed to load database: {}", database.display()))?;

    let format_str = db.format();
    let has_ip = db.has_ip_data();
    let has_literals = db.has_literal_data();
    let has_globs = db.has_glob_data();
    let has_string = has_literals || has_globs;
    let ip_count = db.ip_count();
    let literal_count = db.literal_count();
    let glob_count = db.glob_count();
    let metadata = db.metadata();

    if json_output {
        let mut output = json!({
            "file": database.display().to_string(),
            "format": format_str,
            "has_ip_data": has_ip,
            "has_literal_data": has_literals,
            "has_glob_data": has_globs,
            "has_string_data": has_string,
            "ip_count": ip_count,
            "literal_count": literal_count,
            "glob_count": glob_count,
        });

        if let Some(meta) = metadata {
            output["metadata"] = data_value_to_json(&meta);
        }

        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Database: {}", database.display());
        // Display format based on actual content
        let actual_format = if ip_count > 0 && (literal_count > 0 || glob_count > 0) {
            "Combined IP+String database"
        } else if ip_count > 0 {
            "IP database"
        } else if literal_count > 0 || glob_count > 0 {
            "String database"
        } else {
            "Empty database"
        };
        println!("Format:   {}", actual_format);
        println!();
        println!("Capabilities:");
        // Only show IP lookups as available if there are actual IP entries
        if ip_count > 0 {
            println!("  IP lookups:      ✓");
            println!("    Entries:       {}", ip_count);
        } else {
            println!("  IP lookups:      ✗");
        }
        println!("  String lookups:  {}", if has_string { "✓" } else { "✗" });
        if has_literals {
            println!("    Literals:      ✓ ({} strings)", literal_count);
        }
        if has_globs {
            println!("    Globs:         ✓ ({} patterns)", glob_count);
        }

        if let Some(meta) = metadata {
            if let DataValue::Map(map) = &meta {
                println!();
                println!("Metadata:");

                // Show database_type if present
                if let Some(DataValue::String(db_type)) = map.get("database_type") {
                    println!("  Database type:   {}", db_type);
                }

                // Show description if present
                if let Some(DataValue::Map(desc_map)) = map.get("description") {
                    println!("  Description:");
                    for (lang, desc_value) in desc_map {
                        if let DataValue::String(desc) = desc_value {
                            println!("    {}: {}", lang, desc);
                        }
                    }
                }

                // Show build epoch if present
                if let Some(build_epoch) = map.get("build_epoch") {
                    if let Some(epoch) = extract_uint_from_datavalue(build_epoch) {
                        let timestamp_str = format_unix_timestamp(epoch);
                        println!("  Build time:      {} ({})", timestamp_str, epoch);
                    }
                }

                // Show IP version if present
                if let Some(ip_version) = map.get("ip_version") {
                    if let Some(ver) = extract_uint_from_datavalue(ip_version) {
                        println!("  IP version:      IPv{}", ver);
                    }
                }

                // Show node count if present
                if let Some(node_count) = map.get("node_count") {
                    if let Some(count) = extract_uint_from_datavalue(node_count) {
                        println!("  Node count:      {}", count);
                    }
                }

                // Show record size if present
                if let Some(record_size) = map.get("record_size") {
                    if let Some(size) = extract_uint_from_datavalue(record_size) {
                        println!("  Record size:     {} bits", size);
                    }
                }

                if verbose {
                    println!();
                    println!("Full metadata:");
                    println!("{}", format_data_value(&meta, "  "));
                }
            }
        }
    }

    Ok(())
}
