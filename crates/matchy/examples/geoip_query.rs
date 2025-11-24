use matchy::{Database, QueryResult};
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get command line arguments
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <database.mmdb> [ip_address]", args[0]);
        eprintln!("\nExample:");
        eprintln!("  {} GeoLite2-Country.mmdb 1.1.1.1", args[0]);
        eprintln!("  {} GeoLite2-Country.mmdb 8.8.8.8", args[0]);
        std::process::exit(1);
    }

    let db_path = &args[1];

    // Open the GeoIP database
    println!("Loading database: {}", db_path);
    let db = Database::from(db_path).open()?;
    println!("Database format: {}\n", db.format());

    // If IP address provided, query it
    if args.len() >= 3 {
        let ip = &args[2];
        query_ip(&db, ip)?;
    } else {
        // Demo mode - query several IPs
        println!("Demo mode - querying several IPs:\n");

        let demo_ips = vec![
            "1.1.1.1",              // Cloudflare DNS
            "8.8.8.8",              // Google DNS
            "208.67.222.222",       // OpenDNS
            "2001:4860:4860::8888", // Google IPv6
            "127.0.0.1",            // Localhost (not found)
        ];

        for ip in demo_ips {
            query_ip(&db, ip)?;
            println!();
        }
    }

    Ok(())
}

fn query_ip(db: &Database, ip: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Querying IP: {}", ip);

    match db.lookup(ip)? {
        Some(QueryResult::Ip { data, prefix_len }) => {
            println!("  ✓ Found in database");
            println!("  Prefix length: /{}", prefix_len);
            println!("  Data: {:#?}", data);
        }
        Some(QueryResult::NotFound) => {
            println!("  ✗ Not found in database (e.g., private/reserved IP)");
        }
        Some(QueryResult::Pattern { .. }) => {
            println!("  ! Unexpected pattern result");
        }
        None => {
            println!("  ✗ No result");
        }
    }

    Ok(())
}
