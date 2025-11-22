# Querying

Matchy provides multiple ways to query databases depending on your use case.

## Direct Lookup

The simplest approach is to call `lookup()` with a string:

```rust
use matchy::{Database, QueryResult};

let db = Database::from("threats.mxy").open()?;

if let Some(result) = db.lookup("192.168.1.1")? {
    println!("Found match: {:?}", result);
}
```

See [Database and Querying](../reference/database-query.md) for complete `lookup()` API documentation.

## Extract-and-Lookup Pattern

For scanning unstructured text (logs, emails, documents), use the **extract-and-lookup** pattern:

1. Extract structured patterns (IPs, domains, etc.) from text
2. Look up each extracted pattern in the database
3. Process matches

Matchy provides `lookup_extracted()` to make this pattern efficient and ergonomic.

### Basic Example

```rust
use matchy::{Database, extractor::Extractor};

let db = Database::from("threats.mxy").open()?;
let extractor = Extractor::new()?;

let log_line = b"Connection from 192.168.1.100 to evil.com";

for item in extractor.extract_from_line(log_line) {
    if let Some(result) = db.lookup_extracted(&item, log_line)? {
        println!("⚠️  Threat: {} ({})",
            item.as_str(log_line),
            item.item.type_name()
        );
    }
}
```

**Output:**
```
⚠️  Threat: 192.168.1.100 (IPv4)
⚠️  Threat: evil.com (Domain)
```

### Why use lookup_extracted()?

The `lookup_extracted()` method provides three key benefits:

1. **Performance**: IP addresses use typed lookups (no string parsing)
2. **Ergonomics**: No manual match statement needed
3. **Future-proof**: New extracted types are handled automatically

**Without `lookup_extracted()` (verbose):**
```rust
use std::net::IpAddr;

for item in extractor.extract_from_line(log_line) {
    // Must manually match on each variant
    let result = match &item.item {
        ExtractedItem::Ipv4(ip) => db.lookup_ip(IpAddr::V4(*ip))?,
        ExtractedItem::Ipv6(ip) => db.lookup_ip(IpAddr::V6(*ip))?,
        ExtractedItem::Domain(s) => db.lookup(s)?,
        ExtractedItem::Email(s) => db.lookup(s)?,
        ExtractedItem::Hash(_, s) => db.lookup(s)?,
        ExtractedItem::Bitcoin(s) => db.lookup(s)?,
        ExtractedItem::Ethereum(s) => db.lookup(s)?,
        ExtractedItem::Monero(s) => db.lookup(s)?,
    };
    // Process result...
}
```

**With `lookup_extracted()` (clean):**
```rust
for item in extractor.extract_from_line(log_line) {
    if let Some(result) = db.lookup_extracted(&item, log_line)? {
        // Process result...
    }
}
```

### Real-World Example

Scanning logs for threat intelligence:

```rust
use matchy::{Database, extractor::Extractor, QueryResult};
use std::fs::File;
use std::io::{BufReader, BufRead};

let db = Database::from("threats.mxy").open()?;
let extractor = Extractor::new()?;

let file = File::open("access.log")?;
let reader = BufReader::new(file);

for (line_num, line) in reader.lines().enumerate() {
    let line = line?;
    let line_bytes = line.as_bytes();
    
    for item in extractor.extract_from_line(line_bytes) {
        if let Some(result) = db.lookup_extracted(&item, line_bytes)? {
            // Skip "not found" results
            if matches!(result, QueryResult::NotFound) {
                continue;
            }
            
            eprintln!(
                "Line {}: Found {} ({})",
                line_num + 1,
                item.as_str(line_bytes),
                item.item.type_name()
            );
            
            // Extract threat intel from result
            match result {
                QueryResult::Pattern { data, .. } => {
                    for d in data.iter().flatten() {
                        eprintln!("  Data: {:?}", d);
                    }
                }
                QueryResult::Ip { data, prefix_len } => {
                    eprintln!("  Matched /{} CIDR: {:?}", prefix_len, data);
                }
                _ => {}
            }
        }
    }
}
```

### Extracting Type Information

Each extracted item knows its type:

```rust
for item in extractor.extract_from_line(log_line) {
    let type_name = item.item.type_name();
    // Returns: "IPv4", "IPv6", "Domain", "Email",
    //          "MD5", "SHA1", "SHA256", "SHA384", "SHA512",
    //          "Bitcoin", "Ethereum", "Monero"
    
    println!("Found {} at offset {}", type_name, item.span.0);
}
```

### Multi-Database Lookups

Check multiple databases (e.g., blocklist + allowlist):

```rust
let threats = Database::from("threats.mxy").open()?;
let allowlist = Database::from("allowlist.mxy").open()?;
let extractor = Extractor::new()?;

for item in extractor.extract_from_line(log_line) {
    // Check allowlist first
    if allowlist.lookup_extracted(&item, log_line)?.is_some() {
        continue; // Skip - in allowlist
    }
    
    // Check threats
    if let Some(result) = threats.lookup_extracted(&item, log_line)? {
        println!("⚠️  Threat detected: {}", item.as_str(log_line));
    }
}
```

### Performance Characteristics

- **Extraction**: 200-500 MB/sec throughput
- **Lookup per extracted item**: 
  - IPs: ~138ns (7M queries/sec)
  - Domains: ~112ns-1μs depending on pattern complexity
- **Combined throughput**: Typically 100-300 MB/sec for full extract+lookup pipeline

### See Also

- [Pattern Extraction](extraction.md) - Extractor configuration and features
- [Database Query Reference](../reference/database-query.md) - Complete API documentation
- [Examples](../appendix/examples.md) - Working code examples
