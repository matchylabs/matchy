use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use matchy::DataValue;
use matchy::DatabaseBuilder;
use matchy::MatchMode;
use std::collections::HashMap;
use std::hint::black_box;

// Benchmark: Building MMDB databases with varying levels of data duplication
fn bench_mmdb_build_with_deduplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("mmdb_build");

    // Test with different entry counts and duplication levels
    for entry_count in [100, 500, 1000, 5000].iter() {
        // Case 1: High duplication (10 unique data values, shared across all entries)
        // This is realistic for threat intel, geolocation, etc.
        let high_dedup_data = (0..10)
            .map(|i| {
                let mut map = HashMap::new();
                map.insert(
                    "category".to_string(),
                    DataValue::String(format!("category_{}", i)),
                );
                map.insert("risk".to_string(), DataValue::Uint16((i as u16) * 10));
                map.insert(
                    "description".to_string(),
                    DataValue::String(format!("This is a longer description for category {}", i)),
                );
                map.insert("active".to_string(), DataValue::Bool(i % 2 == 0));
                map
            })
            .collect::<Vec<_>>();

        group.throughput(Throughput::Elements(*entry_count as u64));
        group.bench_with_input(
            BenchmarkId::new("high_dedup_ip", entry_count),
            entry_count,
            |b, &count| {
                b.iter(|| {
                    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
                    for i in 0..count {
                        let ip = format!("192.168.{}.{}", i / 256, i % 256);
                        // Cycle through the 10 data values
                        let data = high_dedup_data[i % 10].clone();
                        builder.add_ip(black_box(&ip), black_box(data)).unwrap();
                    }
                    let db = builder.build().unwrap();
                    black_box(db);
                });
            },
        );

        // Case 2: No duplication (every entry has unique data)
        group.bench_with_input(
            BenchmarkId::new("no_dedup_ip", entry_count),
            entry_count,
            |b, &count| {
                b.iter(|| {
                    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
                    for i in 0..count {
                        let ip = format!("192.168.{}.{}", i / 256, i % 256);
                        let mut data = HashMap::new();
                        data.insert("id".to_string(), DataValue::Uint32(i as u32));
                        data.insert(
                            "unique".to_string(),
                            DataValue::String(format!("unique_value_{}", i)),
                        );
                        builder.add_ip(black_box(&ip), black_box(data)).unwrap();
                    }
                    let db = builder.build().unwrap();
                    black_box(db);
                });
            },
        );

        // Case 3: Medium duplication (50 unique values)
        let medium_dedup_data = (0..50)
            .map(|i| {
                let mut map = HashMap::new();
                map.insert(
                    "country".to_string(),
                    DataValue::String(format!("Country_{}", i)),
                );
                map.insert("code".to_string(), DataValue::Uint16(i as u16));
                map
            })
            .collect::<Vec<_>>();

        group.bench_with_input(
            BenchmarkId::new("medium_dedup_ip", entry_count),
            entry_count,
            |b, &count| {
                b.iter(|| {
                    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
                    for i in 0..count {
                        let ip = format!("192.168.{}.{}", i / 256, i % 256);
                        let data = medium_dedup_data[i % 50].clone();
                        builder.add_ip(black_box(&ip), black_box(data)).unwrap();
                    }
                    let db = builder.build().unwrap();
                    black_box(db);
                });
            },
        );

        // Case 4: Mixed entries (IPs + patterns with shared data)
        group.bench_with_input(
            BenchmarkId::new("mixed_high_dedup", entry_count),
            entry_count,
            |b, &count| {
                b.iter(|| {
                    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
                    for i in 0..count {
                        let data = high_dedup_data[i % 10].clone();
                        if i % 3 == 0 {
                            // IP address
                            let ip = format!("10.0.{}.{}", i / 256, i % 256);
                            builder.add_ip(black_box(&ip), black_box(data)).unwrap();
                        } else if i % 3 == 1 {
                            // Literal pattern
                            let pattern = format!("evil_{}.com", i);
                            builder
                                .add_literal(black_box(&pattern), black_box(data))
                                .unwrap();
                        } else {
                            // Glob pattern
                            let pattern = format!("*.bad_{}.net", i);
                            builder
                                .add_glob(black_box(&pattern), black_box(data))
                                .unwrap();
                        }
                    }
                    let db = builder.build().unwrap();
                    black_box(db);
                });
            },
        );
    }

    group.finish();
}

// Benchmark: Complex nested data structures (realistic for threat intel)
fn bench_mmdb_build_complex_data(c: &mut Criterion) {
    let mut group = c.benchmark_group("mmdb_build_complex");

    // Create realistic threat intel data structure
    let create_complex_data = |category: &str, severity: u16| {
        let mut data = HashMap::new();
        data.insert(
            "category".to_string(),
            DataValue::String(category.to_string()),
        );
        data.insert("severity".to_string(), DataValue::Uint16(severity));

        // Nested metadata
        let mut metadata = HashMap::new();
        metadata.insert("first_seen".to_string(), DataValue::Uint64(1234567890));
        metadata.insert("last_seen".to_string(), DataValue::Uint64(1234567999));
        metadata.insert("confidence".to_string(), DataValue::Float(0.95));
        data.insert("metadata".to_string(), DataValue::Map(metadata));

        // Array of tags
        let tags = vec![
            DataValue::String("malware".to_string()),
            DataValue::String("phishing".to_string()),
            DataValue::String("c2".to_string()),
        ];
        data.insert("tags".to_string(), DataValue::Array(tags));

        data
    };

    // 5 threat categories that will be reused
    let threat_categories = [
        create_complex_data("malware", 8),
        create_complex_data("phishing", 7),
        create_complex_data("spam", 3),
        create_complex_data("c2", 9),
        create_complex_data("scanning", 2),
    ];

    for entry_count in [500, 2000, 5000].iter() {
        group.throughput(Throughput::Elements(*entry_count as u64));
        group.bench_with_input(
            BenchmarkId::new("complex_threat_intel", entry_count),
            entry_count,
            |b, &count| {
                b.iter(|| {
                    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
                    for i in 0..count {
                        let data = threat_categories[i % 5].clone();
                        if i % 2 == 0 {
                            let ip = format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256);
                            builder.add_ip(black_box(&ip), black_box(data)).unwrap();
                        } else {
                            let domain = format!("evil-{}.badactor.com", i);
                            builder
                                .add_literal(black_box(&domain), black_box(data))
                                .unwrap();
                        }
                    }
                    let db = builder.build().unwrap();
                    black_box(db);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_mmdb_build_with_deduplication,
    bench_mmdb_build_complex_data
);
criterion_main!(benches);
