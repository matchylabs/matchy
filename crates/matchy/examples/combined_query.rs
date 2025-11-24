use matchy::{Database, QueryResult};
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <combined-database.pgb> [query]", args[0]);
        eprintln!("\nExample:");
        eprintln!("  {} GeoLite2-Country-Threats.pgb", args[0]);
        eprintln!("  {} GeoLite2-Country-Threats.pgb evil.com", args[0]);
        eprintln!("  {} GeoLite2-Country-Threats.pgb 8.8.8.8", args[0]);
        std::process::exit(1);
    }

    let db_path = &args[1];

    println!("Loading combined database: {}", db_path);
    let db = Database::from(db_path).open()?;
    println!("Format: {}", db.format());
    println!("Has IP data: {}", db.has_ip_data());
    println!("Has literal data: {}", db.has_literal_data());
    println!("Has glob data: {}", db.has_glob_data());
    println!();

    if args.len() >= 3 {
        // Query provided
        let query = &args[2];
        query_database(&db, query)?;
    } else {
        // Demo mode
        println!("Demo mode - testing both IP and pattern lookups:\n");

        println!("=== IP Lookups ===");
        for ip in &["8.8.8.8", "1.1.1.1", "127.0.0.1"] {
            query_database(&db, ip)?;
            println!();
        }

        println!("=== Pattern Lookups ===");
        for pattern in &["evil.com", "malware.cn", "attacker.ru", "safe.com"] {
            query_database(&db, pattern)?;
            println!();
        }
    }

    Ok(())
}

fn query_database(db: &Database, query: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Query: {}", query);

    match db.lookup(query)? {
        Some(QueryResult::Ip { data, prefix_len }) => {
            println!("  ✓ IP Match");
            println!("  Prefix: /{}", prefix_len);
            println!("  Data: {:?}", data);
        }
        Some(QueryResult::Pattern { pattern_ids, data }) => {
            println!("  ✓ Pattern Match");
            println!(
                "  Matched {} pattern(s): {:?}",
                pattern_ids.len(),
                pattern_ids
            );
            for (i, data_opt) in data.iter().enumerate() {
                if let Some(d) = data_opt {
                    println!("    Pattern {}: {:?}", pattern_ids[i], d);
                }
            }
        }
        Some(QueryResult::NotFound) => {
            println!("  ✗ Not found");
        }
        None => {
            println!("  - No result");
        }
    }

    Ok(())
}
