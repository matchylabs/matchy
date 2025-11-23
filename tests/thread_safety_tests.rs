// Thread-safety tests for Database
use matchy::Database;
use std::sync::Arc;
use std::thread;

#[test]
fn test_database_is_send_sync() {
    // Compile-time assertion that Database is Send + Sync
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    
    assert_send::<Database>();
    assert_sync::<Database>();
}

#[test]
fn test_concurrent_queries() {
    // Use GeoLite2 test database (IP lookups)
    let db = Arc::new(
        Database::from("tests/data/GeoLite2-Country.mmdb")
            .open()
            .expect("Failed to open test database")
    );

    // Spawn multiple threads doing IP lookups
    let handles: Vec<_> = (0..8)
        .map(|thread_id| {
            let db = Arc::clone(&db);
            thread::spawn(move || {
                // Each thread does 100 queries (mix of IPs)
                for i in 0..100 {
                    let ip = format!("{}.{}.{}.{}", 1 + thread_id, i % 256, (i / 256) % 256, i % 128);
                    let _ = db.lookup(&ip);
                }
            })
        })
        .collect();

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify stats are sane (8 threads * 100 queries = 800 total)
    let stats = db.stats();
    assert_eq!(stats.total_queries, 800, "Expected 800 total queries");
    println!("Concurrent test passed: {} queries, {:.1}% cache hit rate",
             stats.total_queries, stats.cache_hit_rate() * 100.0);
}

#[test]
fn test_shared_cache_locality() {
    // Test that thread-local caching works correctly
    let db = Arc::new(
        Database::from("tests/data/GeoLite2-Country.mmdb")
            .cache_capacity(100)
            .open()
            .expect("Failed to open test database")
    );

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let db = Arc::clone(&db);
            thread::spawn(move || {
                // Each thread queries the same IP repeatedly
                for _ in 0..100 {
                    let _ = db.lookup("8.8.8.8");
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    let stats = db.stats();
    assert_eq!(stats.total_queries, 400);
    
    // With thread-local caching, first query in each thread is a miss,
    // subsequent 99 are hits. So: 4 misses + 396 hits
    assert_eq!(stats.cache_misses, 4, "Expected 4 cache misses (one per thread)");
    assert_eq!(stats.cache_hits, 396, "Expected 396 cache hits");
    
    println!("Thread-local cache test passed: {:.1}% hit rate", 
             stats.cache_hit_rate() * 100.0);
}
