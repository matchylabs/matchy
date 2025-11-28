# Examples

This appendix contains complete examples demonstrating Matchy usage.

## Threat Intelligence Database

Build a database of malicious IPs and domains:

```rust
use matchy::{Database, DatabaseBuilder, MatchMode, DataValue, QueryResult};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);
    
    // Add known malicious IP
    let mut threat = HashMap::new();
    threat.insert("severity".to_string(), DataValue::String("critical".to_string()));
    threat.insert("type".to_string(), DataValue::String("c2_server".to_string()));
    builder.add_entry("198.51.100.1", threat)?;
    
    // Add botnet CIDR range
    let mut botnet = HashMap::new();
    botnet.insert("severity".to_string(), DataValue::String("high".to_string()));
    botnet.insert("type".to_string(), DataValue::String("botnet".to_string()));
    builder.add_entry("203.0.113.0/24", botnet)?;
    
    // Add phishing domain pattern
    let mut phishing = HashMap::new();
    phishing.insert("category".to_string(), DataValue::String("phishing".to_string()));
    builder.add_entry("*.phishing-site.com", phishing)?;
    
    // Build and save
    let db_bytes = builder.build()?;
    std::fs::write("threats.mxy", &db_bytes)?;
    
    // Query
    let db = Database::open("threats.mxy")?;
    
    if let Some(QueryResult::Ip { data, .. }) = db.lookup("198.51.100.1")? {
        println!("Threat found: {:?}", data);
    }
    
    if let Some(QueryResult::Pattern { data, .. }) = db.lookup("login.phishing-site.com")? {
        println!("Phishing site: {:?}", data[0]);
    }
    
    Ok(())
}
```

## GeoIP Database

Query a MaxMind GeoIP database:

```rust
use matchy::{Database, QueryResult};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Open a standard MaxMind GeoLite2 database
    let db = Database::open("GeoLite2-City.mmdb")?;
    
    // Look up IP address
    match db.lookup("8.8.8.8")? {
        Some(QueryResult::Ip { data, prefix_len }) => {
            println!("IP: 8.8.8.8/{}", prefix_len);
            println!("Data: {:#?}", data);
        }
        _ => println!("Not found"),
    }
    
    Ok(())
}
```

## Multi-Pattern Matching

Match against thousands of patterns efficiently:

```rust
use matchy::{DatabaseBuilder, Database, MatchMode, DataValue};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);
    
    // Add thousands of malicious domain patterns
    for i in 0..50_000 {
        let mut data = HashMap::new();
        data.insert("id".to_string(), DataValue::Uint32(i));
        builder.add_entry(&format!("*.malware{}.com", i), data)?;
    }
    
    let db_bytes = builder.build()?;
    std::fs::write("patterns.mxy", &db_bytes)?;
    
    let db = Database::open("patterns.mxy")?;
    
    // Query against 50,000 patterns - still fast!
    let start = std::time::Instant::now();
    let result = db.lookup("subdomain.malware42.com")?;
    println!("Query time: {:?}", start.elapsed());
    println!("Result: {:?}", result);
    
    Ok(())
}
```

See the [repository examples directory](https://github.com/matchylabs/matchy/tree/main/examples)
for more complete examples.
