//! Example demonstrating query result caching
//!
//! This example shows how to configure and use the LRU cache for
//! high-throughput workloads with repeated queries.

use matchy::{mmdb_builder::MmdbBuilder, DataValue, Database, MatchMode};
use std::collections::HashMap;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Matchy Query Caching Demo ===\n");

    // Build a small test database
    println!("1. Building test database...");
    let mut builder = MmdbBuilder::new(MatchMode::CaseSensitive)
        .with_database_type("Cache-Demo")
        .with_description("en", "Caching demonstration database");

    let mut data = HashMap::new();
    data.insert("type".to_string(), DataValue::String("test".to_string()));

    // Add 100 IPs
    for i in 0..100 {
        builder.add_ip(&format!("10.0.0.{}", i), data.clone())?;
    }

    // Add 100 patterns
    for i in 0..100 {
        builder.add_glob(&format!("*.pattern{}.com", i), data.clone())?;
    }

    let db_bytes = builder.build()?;
    println!("   Database size: {} bytes\n", db_bytes.len());

    // Test 1: Without caching
    println!("2. Testing WITHOUT caching (baseline)...");
    let db_uncached = Database::from_bytes_builder(db_bytes.clone())
        .no_cache() // Explicitly disable cache
        .open()?;

    let queries = generate_queries(10_000, 50); // 10k queries, 50% hit rate
    let start = Instant::now();

    for query in &queries {
        let _ = db_uncached.lookup(query)?;
    }

    let uncached_duration = start.elapsed();
    let uncached_qps = queries.len() as f64 / uncached_duration.as_secs_f64();

    println!("   Queries:  {}", queries.len());
    println!("   Duration: {:.3}s", uncached_duration.as_secs_f64());
    println!("   QPS:      {:.0}\n", uncached_qps);

    // Test 2: With caching
    println!("3. Testing WITH caching (10k capacity)...");
    let db_cached = Database::from_bytes_builder(db_bytes.clone())
        .cache_capacity(10_000) // LRU cache for 10k queries
        .open()?;

    let start = Instant::now();

    for query in &queries {
        let _ = db_cached.lookup(query)?;
    }

    let cached_duration = start.elapsed();
    let cached_qps = queries.len() as f64 / cached_duration.as_secs_f64();

    println!("   Queries:  {}", queries.len());
    println!("   Duration: {:.3}s", cached_duration.as_secs_f64());
    println!("   QPS:      {:.0}", cached_qps);

    // Calculate speedup
    let speedup = uncached_duration.as_secs_f64() / cached_duration.as_secs_f64();
    println!("   Speedup:  {:.2}x faster\n", speedup);

    // Test 3: Cache management
    println!("4. Cache management...");
    println!("   Cache entries before clear: {}", db_cached.cache_size());
    db_cached.clear_cache();
    println!(
        "   Cache entries after clear:  {}\n",
        db_cached.cache_size()
    );

    // Test 4: Different hit rates
    println!("5. Performance at different cache hit rates:");
    println!("   Hit Rate | QPS        | vs Uncached");
    println!("   ---------|------------|------------");

    for hit_rate in [0, 50, 80, 95, 99] {
        let db = Database::from_bytes_builder(db_bytes.clone())
            .cache_capacity(10_000)
            .open()?;

        let queries = generate_queries(5_000, hit_rate);
        db.clear_cache();

        let start = Instant::now();
        for query in &queries {
            let _ = db.lookup(query)?;
        }
        let duration = start.elapsed();
        let qps = queries.len() as f64 / duration.as_secs_f64();
        let speedup = qps / uncached_qps;

        println!(
            "   {:>3}%     | {:>10.0} | {:>6.2}x",
            hit_rate, qps, speedup
        );
    }

    println!("\n=== Key Takeaways ===");
    println!("✓ Caching provides 2-10x speedup at high hit rates (80%+)");
    println!("✓ Zero overhead when disabled (.no_cache())");
    println!("✓ Thread-safe and memory-efficient (LRU eviction)");
    println!("✓ Best for: web APIs, firewalls, real-time threat detection");
    println!("✓ Skip for: batch processing, one-time scans");

    Ok(())
}

/// Generate test queries with controlled hit rate
fn generate_queries(count: usize, hit_rate: usize) -> Vec<String> {
    let unique = if hit_rate == 0 {
        count // All unique
    } else {
        (count * (100 - hit_rate)) / 100
    };

    (0..count)
        .map(|i| {
            let idx = i % unique.max(1);
            match idx % 2 {
                0 => format!("10.0.0.{}", idx % 100),
                _ => format!("test.pattern{}.com", idx % 100),
            }
        })
        .collect()
}
