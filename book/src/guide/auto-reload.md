# Auto-Reload and Callbacks

Matchy supports automatic database reloading when files change, enabling zero-downtime updates in production systems. The auto-reload feature uses lock-free Arc swapping for minimal performance overhead.

## Quick Start

### Rust API

```rust
use matchy::Database;

// Enable auto-reload
let db = Database::from("threats.mxy")
    .auto_reload()
    .open()?;

// Queries automatically use the latest database version
let result = db.lookup("192.168.1.1")?;
```

### C API

```c
#include <matchy/matchy.h>

// Configure auto-reload
matchy_open_options_t opts;
matchy_init_open_options(&opts);
opts.auto_reload = true;

matchy_t *db = matchy_open_with_options("threats.mxy", &opts);

// Queries automatically use latest version
matchy_result_t result;
matchy_lookup(db, "192.168.1.1", &result);

matchy_close(db);
```

## How Auto-Reload Works

When auto-reload is enabled:

1. **File watching** - A background thread monitors the database file using OS notifications
2. **Debouncing** - File changes are debounced (200ms) to avoid rapid reload cycles
3. **Background loading** - New database is loaded in a background thread
4. **Atomic swap** - New database is atomically swapped using lock-free Arc pointer
5. **Graceful handoff** - Old database stays alive until all query threads finish with it

```
┌─────────────┐
│ Query Thread│
│  Thread 1   │──┐
└─────────────┘  │
                 │    ┌──────────────┐     ┌──────────────┐
┌─────────────┐  ├───→│  ArcSwap     │────→│  Database v1 │
│ Query Thread│  │    │ (atomic ptr) │     └──────────────┘
│  Thread 2   │──┤    └──────────────┘            │
└─────────────┘  │           ▲                     │
                 │           │                     │ (stays alive
┌─────────────┐  │    ┌──────────────┐            │  until all
│ Query Thread│  │    │    Watcher   │            │  refs drop)
│  Thread N   │──┘    │    Thread    │            │
└─────────────┘       └──────────────┘            ▼
                             │              ┌──────────────┐
                             │  (atomic     │  Database v2 │
                             └─  swap)      │  (new)       │
                                            └──────────────┘
```

## Performance

Auto-reload has minimal overhead:

- **Per-query cost**: ~1-2 nanoseconds (atomic generation counter check)
- **After first check**: Zero overhead (thread-local Arc caching)
- **No locks**: Pure lock-free atomic operations
- **Scalability**: No contention even with 160+ cores

### Performance Breakdown

```rust
// First query after reload (~1-2ns overhead)
let result = db.lookup("192.168.1.1")?;  // Check generation + cache Arc

// Subsequent queries (zero overhead)
let result = db.lookup("192.168.1.2")?;  // Pure thread-local access
let result = db.lookup("192.168.1.3")?;  // Pure thread-local access
```

The generation check is a single atomic load operation, comparable to checking a boolean flag.

## Reload Callbacks

Get notified when database reloads occur:

### Rust API

```rust
use matchy::{Database, ReloadEvent};

let db = Database::from("threats.mxy")
    .auto_reload()
    .on_reload(|event: ReloadEvent| {
        if event.success {
            println!("✅ Database reloaded successfully");
            println!("   Path: {}", event.path.display());
            println!("   Generation: {}", event.generation);
        } else {
            eprintln!("❌ Database reload failed");
            eprintln!("   Path: {}", event.path.display());
            eprintln!("   Error: {}", event.error.unwrap());
        }
    })
    .open()?;
```

The `ReloadEvent` structure contains:

```rust
pub struct ReloadEvent {
    pub path: PathBuf,           // Database file path
    pub success: bool,            // Whether reload succeeded
    pub error: Option<String>,    // Error message (if failed)
    pub generation: u64,          // Generation counter
}
```

### C API

```c
#include <matchy/matchy.h>
#include <stdio.h>

// Callback function
void on_reload(const matchy_reload_event_t *event, void *user_data) {
    if (event->success) {
        printf("✅ Reloaded: %s (generation %lu)\n",
               event->path, event->generation);
    } else {
        fprintf(stderr, "❌ Reload failed: %s - %s\n",
                event->path, event->error);
    }
}

int main() {
    // Configure callback
    matchy_open_options_t opts;
    matchy_init_open_options(&opts);
    opts.auto_reload = true;
    opts.reload_callback = on_reload;
    opts.reload_callback_user_data = NULL;  // Optional context pointer
    
    matchy_t *db = matchy_open_with_options("threats.mxy", &opts);
    
    // ... use database ...
    
    matchy_close(db);
    return 0;
}
```

### Callback Safety

**Important considerations:**

- Callbacks run on the **watcher thread**, not query threads
- Keep callbacks **fast and non-blocking**
- Do **not** call matchy query functions from callbacks (potential deadlock)
- Copy `event.path` and `event.error` if you need them after callback returns
- Callbacks must be **thread-safe**

## Use Cases

### Production Threat Intelligence

```rust
// Threat database updated hourly from feed
let db = Database::from("/data/threats.mxy")
    .auto_reload()
    .on_reload(|event| {
        if event.success {
            // Log to monitoring system
            metrics::increment_counter!("db_reload_success");
            info!("Threat database updated: generation {}", event.generation);
        } else {
            // Alert on failure
            metrics::increment_counter!("db_reload_failure");
            error!("Failed to reload threats: {:?}", event.error);
        }
    })
    .open()?;

// Queries automatically use latest threat data
for log_entry in log_stream {
    if let Some(threat) = db.lookup(&log_entry.ip)? {
        alert_security_team(log_entry, threat);
    }
}
```

### GeoIP Database Updates

```rust
// GeoIP database refreshed weekly
let geoip = Database::from("/data/GeoLite2-City.mmdb")
    .auto_reload()
    .on_reload(|event| {
        println!("GeoIP database updated: {}", event.path.display());
    })
    .open()?;

// No service restart needed for updates
let location = geoip.lookup("8.8.8.8")?;
```

### Multi-Process Deployment

```rust
// Worker process
let db = Arc::new(
    Database::from("threats.mxy")
        .auto_reload()
        .open()?
);

// Spawn multiple worker threads
for i in 0..num_cpus::get() {
    let db_clone = Arc::clone(&db);
    thread::spawn(move || {
        // Each thread automatically gets reloaded database
        loop {
            let work = get_work();
            let result = db_clone.lookup(&work.query)?;
            process_result(result);
        }
    });
}
```

## Database Update Best Practices

### Atomic File Replacement

Always use atomic rename for updates:

```bash
# Build new database
matchy build new-threats.csv -o threats.mxy.tmp

# Atomic rename (works on all platforms)
mv threats.mxy.tmp threats.mxy
```

This ensures:
- No partial database reads
- Auto-reload detects the change
- Zero query errors during update

### Update Scripts

```bash
#!/bin/bash
# update-threats.sh - Safe database update script

set -e

DB_PATH="/data/threats.mxy"
TEMP_DB="${DB_PATH}.tmp"

# Download and build new database
curl -o threats.csv "https://threat-feed.example.com/latest"
matchy build threats.csv -o "$TEMP_DB"

# Validate before deploying
matchy validate "$TEMP_DB" --level strict

# Atomic replace
mv "$TEMP_DB" "$DB_PATH"

echo "✅ Database updated successfully"
```

### Monitoring Reloads

```rust
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

let reload_count = Arc::new(AtomicU64::new(0));
let reload_count_clone = Arc::clone(&reload_count);

let db = Database::from("threats.mxy")
    .auto_reload()
    .on_reload(move |event| {
        if event.success {
            reload_count_clone.fetch_add(1, Ordering::Relaxed);
        }
    })
    .open()?;

// Later: check reload metrics
let reloads = reload_count.load(Ordering::Relaxed);
println!("Database has been reloaded {} times", reloads);
```

## Limitations

### File System Events

- **Linux**: Uses inotify (requires kernel support)
- **macOS**: Uses FSEvents (works with atomic renames)
- **Windows**: Uses ReadDirectoryChangesW
- **Network filesystems**: May have delayed notifications (NFS, CIFS, etc.)

### Debouncing

File changes are debounced for 200ms to avoid rapid reload cycles. If your build process writes the file in multiple stages, only the final change triggers reload.

### Memory Usage

During reload, both old and new databases are in memory briefly:

```
Normal:  1x database size
Reload:  2x database size (temporary)
```

Old database is freed once all query threads release their references (typically <1 second).

## Troubleshooting

### Reload Not Triggering

**Check file watcher**:
```rust
// Enable debug logging
RUST_LOG=matchy=debug cargo run
```

**Verify file changes**:
```bash
# Check file modification time
stat threats.mxy

# Force update
touch threats.mxy
```

### Callbacks Not Firing

Ensure callback is set before database changes:

```rust
// ❌ Wrong: callback set after database loaded
let db = Database::from("threats.mxy").auto_reload().open()?;
// Database changes here won't trigger callback yet

// ✅ Correct: callback set during open
let db = Database::from("threats.mxy")
    .auto_reload()
    .on_reload(|e| println!("Reloaded!"))
    .open()?;
```

### Performance Impact

If auto-reload overhead is too high:

```rust
// Measure overhead
let start = Instant::now();
for i in 0..1_000_000 {
    db.lookup("192.168.1.1")?;
}
println!("Time: {:?}", start.elapsed());
```

Expected: <1-2ns per query overhead. If higher, check for:
- Very high query rate (>100M QPS per thread)
- NUMA architecture with poor cache affinity
- Excessive reloads (reduce update frequency)

## Next Steps

- [Performance Considerations](performance.md) - Detailed performance analysis
- [Query Result Caching](caching.md) - Combine with caching for maximum throughput
- [Examples](../appendix/examples.md) - Complete working examples
