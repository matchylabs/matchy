use anyhow::{Context, Result};
use matchy::{Database, QueryResult};
use serde_json::json;
use std::path::PathBuf;

use crate::cli_utils::{data_value_to_json, format_cidr};

pub fn cmd_query(database: PathBuf, query: String, quiet: bool) -> Result<()> {
    // Load database using fluent API
    let db = Database::from(database.to_str().unwrap())
        .open()
        .with_context(|| format!("Failed to load database: {}", database.display()))?;

    // Perform the query (auto-detects IP vs pattern)
    let result = db
        .lookup(&query)
        .with_context(|| format!("Query failed for: {}", query))?;

    // Determine if match was found (for exit code)
    let found = matches!(result, Some(QueryResult::Pattern { ref pattern_ids, .. }) if !pattern_ids.is_empty())
        || matches!(result, Some(QueryResult::Ip { .. }));

    if quiet {
        // Quiet mode: no output, just exit code
        std::process::exit(if found { 0 } else { 1 });
    }

    // Default: JSON output with data - always return array for consistency
    match result {
        Some(QueryResult::Pattern { pattern_ids, data }) => {
            if pattern_ids.is_empty() {
                // No matches - return empty array
                println!("[]");
            } else {
                // Build match results - only include data, not internal pattern IDs
                let mut results = Vec::new();
                for (i, &_pattern_id) in pattern_ids.iter().enumerate() {
                    // Always include data if available
                    if let Some(Some(ref d)) = data.get(i) {
                        results.push(data_value_to_json(d));
                    }
                }

                // Return array of matches (just the data)
                println!("{}", serde_json::to_string_pretty(&json!(results))?);
            }
        }
        Some(QueryResult::Ip { data, prefix_len }) => {
            let cidr = format_cidr(&query, prefix_len);
            let mut result = data_value_to_json(&data);

            // Add CIDR info to the data object
            if let serde_json::Value::Object(ref mut map) = result {
                map.insert("cidr".to_string(), json!(cidr));
                map.insert("prefix_len".to_string(), json!(prefix_len));
            }

            // Return as array with single element
            println!("{}", serde_json::to_string_pretty(&json!([result]))?);
        }
        Some(QueryResult::NotFound) | None => {
            // Not found - return empty array
            println!("[]");
        }
    }

    // Exit with appropriate code
    std::process::exit(if found { 0 } else { 1 });
}
