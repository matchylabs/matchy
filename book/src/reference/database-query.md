# Database and Querying

`Database` opens and queries databases. See [First Database with Rust](../getting-started/api-rust-first.md)
for a tutorial.

## Opening a Database

### Basic Opening

```rust path=null start=null
use matchy::Database;

// Simple - uses defaults (cache enabled, validation on)
let db = Database::from("database.mxy").open()?;
```

The database is memory-mapped and loads in under 1 millisecond regardless of size.

### Builder API

The recommended way to open databases uses the fluent builder API:

```rust path=null start=null
use matchy::Database;

// With custom cache size
let db = Database::from("database.mxy")
    .cache_capacity(1000)
    .open()?;

// Large cache for high repetition workloads
let db = Database::from("threats.mxy")
    .cache_capacity(100_000)
    .open()?;

// No cache (for unique queries)
let db = Database::from("database.mxy")
    .no_cache()
    .open()?;
```

### Builder Methods

| Method | Description |
|--------|-------------|
| `.cache_capacity(size)` | Set LRU cache size (default: 10,000) |
| `.no_cache()` | Disable caching entirely |
| `.open()` | Load the database |

**Cache Size Guidelines**:
- `0` (via `.no_cache()`): No caching - best for diverse queries
- `100-1000`: Good for moderate repetition
- `10,000` (default): Optimal for typical workloads
- `100,000+`: For very high repetition (80%+ hit rate)

**Note**: Caching only benefits pattern lookups with high repetition. IP and literal lookups are already fast and don't benefit from caching.

### Error Handling

```rust
match Database::open("database.mxy") {
    Ok(db) => { /* success */ }
    Err(MatchyError::FileNotFound { path }) => {
        eprintln!("Database not found: {}", path);
    }
    Err(MatchyError::InvalidFormat { reason }) => {
        eprintln!("Invalid database format: {}", reason);
    }
    Err(e) => eprintln!("Error: {}", e),
}
```

## Querying

### lookup() - Direct String Lookup

```rust
pub fn lookup<S: AsRef<str>>(&self, query: S) -> Result<Option<QueryResult>, MatchyError>
```

Basic usage:

```rust
match db.lookup("192.0.2.1")? {
    Some(result) => println!("Found: {:?}", result),
    None => println!("Not found"),
}
```

### lookup_extracted() - Lookup After Extraction

```rust
pub fn lookup_extracted(
    &self,
    item: &matchy::extractor::Match,
    input: &[u8],
) -> Result<Option<QueryResult>, DatabaseError>
```

Efficient lookup for extracted patterns. Automatically uses the optimal lookup path:
- IP addresses use typed `lookup_ip()` (avoids string parsing)
- Other types use string-based `lookup()`

**Usage:**

```rust
use matchy::{Database, extractor::Extractor};

let db = Database::from("threats.mxy").open()?;
let extractor = Extractor::new()?;

let log_line = b"Connection from 192.168.1.1 to evil.com";

for item in extractor.extract_from_line(log_line) {
    if let Some(result) = db.lookup_extracted(&item, log_line)? {
        println!("Match: {} (type: {})",
            item.as_str(log_line),
            item.item.type_name()
        );
    }
}
```

**Why use this?**

1. **Cleaner code**: No manual matching on `ExtractedItem` variants
2. **Better performance**: IP addresses use direct typed lookups
3. **Future-proof**: New extracted types work automatically

**Parameters:**
- `item`: The extracted match from `Extractor`
- `input`: Original input buffer (needed to extract string slices)

**Returns:** `Ok(Some(QueryResult))` if found, `Ok(None)` if not found

See the [Querying guide](../guide/querying.md#extract-and-lookup-pattern) for more examples.

## QueryResult Types

`QueryResult` is an enum with three variants:

### IP Match

```rust
QueryResult::Ip {
    data: Option<HashMap<String, DataValue>>,
    prefix_len: u8,
}
```

Example:
```rust
match db.lookup("192.0.2.1")? {
    Some(QueryResult::Ip { data, prefix_len }) => {
        println!("Matched IP with prefix /{}", prefix_len);
        if let Some(d) = data {
            println!("Data: {:?}", d);
        }
    }
    _ => {}
}
```

### Pattern Match

```rust
QueryResult::Pattern {
    pattern_ids: Vec<u32>,
    data: Vec<Option<HashMap<String, DataValue>>>,
}
```

Example:
```rust
match db.lookup("mail.google.com")? {
    Some(QueryResult::Pattern { pattern_ids, data }) => {
        println!("Matched {} pattern(s)", pattern_ids.len());
        for (i, pattern_data) in data.iter().enumerate() {
            println!("Pattern {}: {:?}", pattern_ids[i], pattern_data);
        }
    }
    _ => {}
}
```

**Note**: A query can match multiple patterns. All matching patterns are returned.

### Exact String Match

```rust
QueryResult::ExactString {
    data: Option<HashMap<String, DataValue>>,
}
```

Example:
```rust
match db.lookup("example.com")? {
    Some(QueryResult::ExactString { data }) => {
        println!("Exact match: {:?}", data);
    }
    _ => {}
}
```

## Complete Example

```rust
use matchy::{Database, QueryResult};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = Database::open("database.mxy")?;
    
    // Query different types
    let queries = vec![
        "192.0.2.1",           // IP
        "10.5.5.5",            // CIDR
        "test.example.com",    // Pattern
        "example.com",         // Exact string
    ];
    
    for query in queries {
        match db.lookup(query)? {
            Some(QueryResult::Ip { prefix_len, .. }) => {
                println!("{}: IP match (/{prefix_len})", query);
            }
            Some(QueryResult::Pattern { pattern_ids, .. }) => {
                println!("{}: Pattern match ({} patterns)", query, pattern_ids.len());
            }
            Some(QueryResult::ExactString { .. }) => {
                println!("{}: Exact match", query);
            }
            None => {
                println!("{}: No match", query);
            }
        }
    }
    
    Ok(())
}
```

## Thread Safety

`Database` is `Send + Sync` and can be safely shared across threads:

```rust
use std::sync::Arc;
use std::thread;

let db = Arc::new(Database::open("database.mxy")?);

let handles: Vec<_> = (0..4).map(|i| {
    let db = Arc::clone(&db);
    thread::spawn(move || {
        db.lookup(&format!("192.0.2.{}", i))
    })
}).collect();

for handle in handles {
    handle.join().unwrap()?;
}
```

## Performance

Query performance by entry type:

- **IP addresses**: ~7 million queries/second (138ns avg)
- **Exact strings**: ~8 million queries/second (112ns avg)
- **Patterns**: ~1-2 million queries/second (500ns-1μs avg)

See [Performance Considerations](../guide/performance.md) for details.

## Database Statistics

### Get Statistics

Retrieve comprehensive statistics about database usage:

```rust path=null start=null
use matchy::Database;

let db = Database::from("threats.mxy").open()?;

// Do some queries
db.lookup("1.2.3.4")?;
db.lookup("example.com")?;
db.lookup("test.com")?;

// Get stats
let stats = db.stats();
println!("Total queries: {}", stats.total_queries);
println!("Queries with match: {}", stats.queries_with_match);
println!("Cache hit rate: {:.1}%", stats.cache_hit_rate() * 100.0);
println!("Match rate: {:.1}%", stats.match_rate() * 100.0);
println!("IP queries: {}", stats.ip_queries);
println!("String queries: {}", stats.string_queries);
```

### DatabaseStats Structure

```rust path=null start=null
pub struct DatabaseStats {
    pub total_queries: u64,
    pub queries_with_match: u64,
    pub queries_without_match: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub ip_queries: u64,
    pub string_queries: u64,
}

impl DatabaseStats {
    pub fn cache_hit_rate(&self) -> f64
    pub fn match_rate(&self) -> f64
}
```

**Helper Methods:**
- `cache_hit_rate()` - Returns cache hit rate as a value from 0.0 to 1.0
- `match_rate()` - Returns query match rate as a value from 0.0 to 1.0

### Interpreting Statistics

**Cache Performance:**
- Hit rate < 50%: Consider disabling cache (`.no_cache()`)
- Hit rate 50-80%: Cache is helping moderately
- Hit rate > 80%: Cache is very effective

**Query Distribution:**
- High `ip_queries`: Database is being used for IP lookups
- High `string_queries`: Database is being used for domain/pattern matching

## Cache Management

### Clear Cache

Remove all cached query results:

```rust path=null start=null
use matchy::Database;

let db = Database::from("threats.mxy").open()?;

// Do some queries (fills cache)
db.lookup("example.com")?;

// Clear cache to force fresh lookups
db.clear_cache();
```

Useful for benchmarking or when you need to ensure fresh lookups without reopening the database.

## Helper Methods

### Checking Entry Types

```rust path=null start=null
if let Some(QueryResult::Ip { .. }) = result {
    // Handle IP match
}
```

Or using match guards:

```rust
match db.lookup(query)? {
    Some(QueryResult::Ip { prefix_len, .. }) if prefix_len == 32 => {
        println!("Exact IP match");
    }
    Some(QueryResult::Ip { prefix_len, .. }) => {
        println!("CIDR match /{}", prefix_len);
    }
    _ => {}
}
```

## Database Lifecycle

Databases are immutable once opened:

```rust
let db = Database::open("database.mxy")?;
// db.lookup(...) - OK
// db.add_entry(...) - No such method!
```

To update a database:
1. Build a new database with `DatabaseBuilder`
2. Write to a temporary file
3. Atomically replace the old database

```rust
// Build new database
let db_bytes = builder.build()?;
std::fs::write("database.mxy.tmp", &db_bytes)?;
std::fs::rename("database.mxy.tmp", "database.mxy")?;

// Reopen
let db = Database::open("database.mxy")?;
```

## See Also

- [DatabaseBuilder](database-builder.md) - Building databases
- [Data Types Reference](data-types-ref.md) - Data value types
- [Performance Considerations](../guide/performance.md) - Optimization
