use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use matchy::{Database, DatabaseBuilder, MatchMode};
use std::collections::HashMap;
use std::hint::black_box;
use std::time::Duration;

/// Benchmark cache overhead at different hit rates
fn bench_cache_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_comparison");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);

    // Build a small test database with IPs, literals, and patterns
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
    let empty_data = HashMap::new();

    // Add 100 IPs
    for i in 0..100 {
        builder
            .add_ip(&format!("10.0.0.{}", i), empty_data.clone())
            .unwrap();
    }

    // Add 100 literals
    for i in 0..100 {
        builder
            .add_literal(&format!("literal_{}.example.com", i), empty_data.clone())
            .unwrap();
    }

    // Add 100 patterns
    for i in 0..100 {
        builder
            .add_glob(&format!("*.pattern{}.com", i), empty_data.clone())
            .unwrap();
    }

    let db_bytes = builder.build().unwrap();

    // Test different cache hit rates: 0%, 50%, 80%, 95%, 99%
    for hit_rate in [0, 50, 80, 95, 99] {
        // Calculate unique queries to achieve target hit rate
        let total_queries = 10000;
        let unique_queries = if hit_rate == 0 {
            total_queries // All unique
        } else {
            (total_queries * (100 - hit_rate)) / 100
        };

        // Generate query set
        let queries: Vec<String> = (0..total_queries)
            .map(|i| {
                let query_idx = i % unique_queries.max(1);
                match query_idx % 3 {
                    // Generate unique queries based on query_idx, not % 100
                    // This way we get as many unique queries as specified by unique_queries
                    0 => format!(
                        "10.{}.{}.{}",
                        query_idx / 256,
                        (query_idx / 16) % 256,
                        query_idx % 256
                    ),
                    1 => format!("literal_{}.example.com", query_idx),
                    _ => format!("test.pattern{}.com", query_idx),
                }
            })
            .collect();

        // Benchmark WITH cache (10k capacity, explicitly enabled)
        // Create DB once, clear cache between iterations
        let db_cached = Database::from_bytes_builder(db_bytes.clone())
            .cache_capacity(10000)
            .open()
            .unwrap();

        group.throughput(Throughput::Elements(total_queries as u64));
        group.bench_with_input(
            BenchmarkId::new("with_cache", format!("{}%_hits", hit_rate)),
            &queries,
            |b, queries| {
                b.iter(|| {
                    // Clear cache before each iteration to get accurate hit rate measurement
                    db_cached.clear_cache();

                    for q in queries {
                        let result = db_cached.lookup(black_box(q)).unwrap();
                        black_box(result);
                    }
                });
            },
        );

        // Benchmark WITHOUT cache (explicitly disabled)
        let db_uncached = Database::from_bytes_builder(db_bytes.clone())
            .no_cache()
            .open()
            .unwrap();

        group.bench_with_input(
            BenchmarkId::new("no_cache", format!("{}%_hits", hit_rate)),
            &queries,
            |b, queries| {
                b.iter(|| {
                    // No cache to clear, just run queries
                    for q in queries {
                        let result = db_uncached.lookup(black_box(q)).unwrap();
                        black_box(result);
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark cache overhead for single query types (100% hit rate)
/// This shows the maximum benefit and overhead of caching
fn bench_cache_by_type(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_by_query_type");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(100);

    // Build database
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
    let empty_data = HashMap::new();

    for i in 0..100 {
        builder
            .add_ip(&format!("10.0.0.{}", i), empty_data.clone())
            .unwrap();
        builder
            .add_literal(&format!("literal_{}.com", i), empty_data.clone())
            .unwrap();
        builder
            .add_glob(&format!("*.pattern{}.com", i), empty_data.clone())
            .unwrap();
    }

    let db_bytes = builder.build().unwrap();

    // Test each query type separately with 100% hit rate (same query repeated)
    let test_cases = vec![
        ("ip", vec!["10.0.0.42"; 1000]),
        ("literal", vec!["literal_42.com"; 1000]),
        ("pattern", vec!["test.pattern42.com"; 1000]),
    ];

    for (query_type, queries) in test_cases {
        // With cache (should be fast after first hit)
        let db_cached = Database::from_bytes_builder(db_bytes.clone())
            .cache_capacity(10000)
            .open()
            .unwrap();

        group.throughput(Throughput::Elements(queries.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("cached", query_type),
            &queries,
            |b, queries| {
                b.iter(|| {
                    for q in queries {
                        let result = db_cached.lookup(black_box(*q)).unwrap();
                        black_box(result);
                    }
                });
            },
        );

        // Without cache (every query is fresh)
        let db_uncached = Database::from_bytes_builder(db_bytes.clone())
            .no_cache()
            .open()
            .unwrap();

        group.bench_with_input(
            BenchmarkId::new("uncached", query_type),
            &queries,
            |b, queries| {
                b.iter(|| {
                    for q in queries {
                        let result = db_uncached.lookup(black_box(*q)).unwrap();
                        black_box(result);
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_cache_comparison, bench_cache_by_type);
criterion_main!(benches);
