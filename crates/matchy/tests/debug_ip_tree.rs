use matchy::database::Database;
use matchy::mmdb_builder::DatabaseBuilder;
use matchy::MatchMode;
use std::collections::HashMap;

#[test]
fn debug_simple_sparse_ips() {
    // Insert just two IPs: 0.0.0.1 and 0.0.0.3
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
    let empty_data = HashMap::new();

    println!("\nInserting 0.0.0.1");
    builder.add_ip("0.0.0.1", empty_data.clone()).unwrap();

    println!("Inserting 0.0.0.3");
    let mut unique_data = HashMap::new();
    unique_data.insert("id".to_string(), matchy::DataValue::Uint32(3));
    builder.add_ip("0.0.0.3", unique_data).unwrap();

    println!("Building database...");
    let db_bytes = builder.build().unwrap();
    println!("Database size: {} bytes", db_bytes.len());

    let db = Database::from_bytes(db_bytes).unwrap();

    // Test each IP from 0.0.0.0 to 0.0.0.7
    for i in 0..8 {
        let ip_str = format!("0.0.0.{}", i);
        let ip = ip_str.parse().unwrap();
        let result = db.lookup_ip(ip).unwrap();

        let expected = i == 1 || i == 3;
        let found = match result {
            Some(matchy::database::QueryResult::NotFound) => false,
            Some(_) => true,
            None => false,
        };

        println!(
            "  {} -> {} (expected: {}){}",
            ip_str,
            if found { "FOUND" } else { "NOT FOUND" },
            if expected { "FOUND" } else { "NOT FOUND" },
            if found == expected {
                " ✓"
            } else {
                " ✗ WRONG!"
            }
        );

        if found != expected {
            if let Some(res) = result {
                println!(
                    "    Details: data_offset={}, prefix_len={}",
                    match res {
                        matchy::database::QueryResult::Ip { prefix_len, .. } =>
                            format!("{}", prefix_len),
                        _ => "N/A".to_string(),
                    },
                    match res {
                        matchy::database::QueryResult::Ip { prefix_len, .. } => prefix_len,
                        _ => 0,
                    }
                );
            }
        }
    }
}
