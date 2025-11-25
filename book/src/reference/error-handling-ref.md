# Error Handling Reference

All fallible operations in Matchy return `Result<T, MatchyError>`.

## MatchyError Type

```rust
pub enum MatchyError {
    /// File does not exist
    FileNotFound { path: String },
    
    /// Invalid database format
    InvalidFormat { reason: String },
    
    /// Corrupted database data
    CorruptData { offset: usize, reason: String },
    
    /// Invalid entry (IP, pattern, string)
    InvalidEntry { entry: String, reason: String },
    
    /// I/O error
    IoError(std::io::Error),
    
    /// Memory mapping failed
    MmapError(String),
    
    /// Pattern compilation failed
    PatternError { pattern: String, reason: String },
    
    /// Internal error
    InternalError(String),
}
```

## Common Error Patterns

### Opening a Database

```rust
use matchy::{Database, MatchyError};

match Database::open("database.mxy") {
    Ok(db) => { /* success */ }
    Err(MatchyError::FileNotFound { path }) => {
        eprintln!("Database not found: {}", path);
        // Handle missing file - maybe create default?
    }
    Err(MatchyError::InvalidFormat { reason }) => {
        eprintln!("Invalid format: {}", reason);
        // File exists but not valid matchy database
    }
    Err(MatchyError::CorruptData { offset, reason }) => {
        eprintln!("Corrupted at offset {}: {}", offset, reason);
        // Database is damaged - rebuild required
    }
    Err(e) => {
        eprintln!("Unexpected error: {}", e);
        return Err(e.into());
    }
}
```

### Building a Database

```rust
use matchy::{DatabaseBuilder, MatchyError};

let mut builder = DatabaseBuilder::new();

// Add entries with error handling
match builder.add_ip_entry("192.0.2.1/32", None) {
    Ok(_) => {}
    Err(MatchyError::InvalidEntry { entry, reason }) => {
        eprintln!("Invalid IP '{}': {}", entry, reason);
        // Skip this entry and continue
    }
    Err(e) => return Err(e.into()),
}

// Build with error handling
match builder.build() {
    Ok(bytes) => {
        std::fs::write("database.mxy", &bytes)?;
    }
    Err(MatchyError::InternalError(msg)) => {
        eprintln!("Build failed: {}", msg);
        return Err(msg.into());
    }
    Err(e) => return Err(e.into()),
}
```

### Querying

```rust
use matchy::{Database, MatchyError};

let db = Database::open("database.mxy")?;

match db.lookup("example.com") {
    Ok(Some(result)) => {
        println!("Found: {:?}", result);
    }
    Ok(None) => {
        println!("Not found");
    }
    Err(MatchyError::CorruptData { offset, reason }) => {
        eprintln!("Data corruption at {}: {}", offset, reason);
        // Database may be partially readable
    }
    Err(e) => {
        eprintln!("Lookup error: {}", e);
        return Err(e.into());
    }
}
```

## Error Context

Use `context` methods to add helpful information:

```rust
use matchy::Database;

fn load_db(path: &str) -> Result<Database, Box<dyn std::error::Error>> {
    Database::open(path)
        .map_err(|e| format!("Failed to load database from '{}': {}", path, e).into())
}
```

Or with `anyhow`:

```rust
use anyhow::{Context, Result};
use matchy::Database;

fn load_db(path: &str) -> Result<Database> {
    Database::open(path)
        .with_context(|| format!("Failed to load database from '{}'", path))
}
```

## Validation Errors

### IP Address Validation

```rust
builder.add_ip_entry("not-an-ip", None)?;
// Error: InvalidEntry { entry: "not-an-ip", reason: "Invalid IP address" }

builder.add_ip_entry("192.0.2.1/33", None)?;
// Error: InvalidEntry { entry: "192.0.2.1/33", reason: "Invalid prefix length" }
```

### Pattern Validation

```rust
builder.add_pattern_entry("*.*.com", None)?;
// Error: PatternError { pattern: "*.*.com", reason: "Multiple wildcards" }

builder.add_pattern_entry("[invalid", None)?;
// Error: PatternError { pattern: "[invalid", reason: "Unclosed bracket" }
```

### String Validation

```rust
builder.add_exact_entry("", None)?;
// Error: InvalidEntry { entry: "", reason: "Empty string" }
```

## Error Recovery

### Partial Success

Continue after validation errors:

```rust
let entries = vec!["192.0.2.1", "not-valid", "10.0.0.1"];
let mut success_count = 0;
let mut error_count = 0;

for entry in entries {
    match builder.add_ip_entry(entry, None) {
        Ok(_) => success_count += 1,
        Err(e) => {
            eprintln!("Skipping invalid entry '{}': {}", entry, e);
            error_count += 1;
        }
    }
}

println!("Added {} entries, skipped {} invalid", success_count, error_count);
```

### Fallback Databases

```rust
let db = Database::open("primary.mxy")
    .or_else(|_| Database::open("backup.mxy"))
    .or_else(|_| Database::open("default.mxy"))?;
```

### Retry Logic

```rust
use std::time::Duration;
use std::thread;

fn open_with_retry(path: &str, max_attempts: u32) -> Result<Database, MatchyError> {
    for attempt in 1..=max_attempts {
        match Database::open(path) {
            Ok(db) => return Ok(db),
            Err(MatchyError::IoError(_)) if attempt < max_attempts => {
                eprintln!("Attempt {} failed, retrying...", attempt);
                thread::sleep(Duration::from_millis(100 * attempt as u64));
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}
```

## Display Implementation

All errors implement `Display`:

```rust
use matchy::MatchyError;

let err = MatchyError::FileNotFound { 
    path: "missing.mxy".to_string() 
};

println!("{}", err);
// Output: Database file not found: missing.mxy

eprintln!("Error: {}", err);
// Stderr: Error: Database file not found: missing.mxy
```

## Error Conversion

### To std::io::Error

```rust
impl From<MatchyError> for std::io::Error {
    fn from(err: MatchyError) -> Self {
        match err {
            MatchyError::FileNotFound { path } => {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Database not found: {}", path)
                )
            }
            MatchyError::IoError(e) => e,
            _ => std::io::Error::new(std::io::ErrorKind::Other, err.to_string()),
        }
    }
}
```

### To `Box<dyn Error>`

```rust
fn do_work() -> Result<(), Box<dyn std::error::Error>> {
    let db = Database::open("db.mxy")?;
    // MatchyError automatically converts
    Ok(())
}
```

## Best Practices

### 1. Match Specific Errors First

```rust
match db.lookup(query) {
    Ok(Some(result)) => { /* handle result */ }
    Ok(None) => { /* handle not found */ }
    Err(MatchyError::CorruptData { .. }) => { /* handle corruption */ }
    Err(e) => { /* generic handler */ }
}
```

### 2. Provide Context

```rust
builder.add_ip_entry(ip, data)
    .map_err(|e| format!("Failed to add IP '{}': {}", ip, e))?;
```

### 3. Log Errors

```rust
use log::{error, warn};

match Database::open(path) {
    Ok(db) => db,
    Err(e) => {
        error!("Failed to open database '{}': {}", path, e);
        return Err(e.into());
    }
}
```

### 4. Use Result Type Aliases

```rust
type Result<T> = std::result::Result<T, MatchyError>;

fn my_function() -> Result<Database> {
    Database::open("database.mxy")
}
```

## Complete Example

```rust
use matchy::{Database, DatabaseBuilder, MatchyError};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Try to open existing database
    let db = match Database::open("cache.mxy") {
        Ok(db) => {
            println!("Loaded existing database");
            db
        }
        Err(MatchyError::FileNotFound { .. }) => {
            println!("Building new database...");
            build_database()?
        }
        Err(e) => {
            eprintln!("Error opening database: {}", e);
            return Err(e.into());
        }
    };
    
    // Query with error handling
    let queries = vec!["192.0.2.1", "example.com", "*.google.com"];
    for query in queries {
        match db.lookup(query) {
            Ok(Some(result)) => {
                println!("{}: {:?}", query, result);
            }
            Ok(None) => {
                println!("{}: Not found", query);
            }
            Err(e) => {
                eprintln!("{}: Error - {}", query, e);
            }
        }
    }
    
    Ok(())
}

fn build_database() -> Result<Database, Box<dyn std::error::Error>> {
    let mut builder = DatabaseBuilder::new();
    
    // Add entries with individual error handling
    let entries = vec![
        ("192.0.2.1", "Valid IP"),
        ("not-an-ip", "Invalid - will skip"),
        ("10.0.0.0/8", "Valid CIDR"),
    ];
    
    for (entry, description) in entries {
        match builder.add_ip_entry(entry, None) {
            Ok(_) => println!("Added: {} ({})", entry, description),
            Err(e) => eprintln!("Skipped: {} - {}", entry, e),
        }
    }
    
    // Build and save
    let db_bytes = builder.build()?;
    fs::write("cache.mxy", &db_bytes)?;
    
    // Reopen
    Database::open("cache.mxy").map_err(Into::into)
}
```

## See Also

- [DatabaseBuilder](database-builder.md) - Building with validation
- [Database Querying](database-query.md) - Query errors
- [Rust Error Handling](https://doc.rust-lang.org/book/ch09-00-error-handling.html)
