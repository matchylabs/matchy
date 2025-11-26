use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use matchy::{mmdb_builder::DatabaseBuilder, DataValue, Database, MatchMode};
use std::collections::HashMap;
use std::fs;
use std::hint::black_box;
use tempfile::TempDir;

fn create_test_database(path: &std::path::Path) {
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
    let mut data = HashMap::new();
    data.insert(
        "threat_level".to_string(),
        DataValue::String("high".to_string()),
    );

    // Add some test data
    for i in 0..1000 {
        builder
            .add_literal(&format!("threat{}.com", i), data.clone())
            .unwrap();
    }

    let bytes = builder.build().unwrap();
    fs::write(path, bytes).unwrap();
}

fn bench_reload_overhead(c: &mut Criterion) {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("bench.mxy");
    create_test_database(&db_path);

    let mut group = c.benchmark_group("auto_reload_overhead");
    group.throughput(Throughput::Elements(1));

    // Benchmark WITHOUT auto-reload (baseline)
    let db_no_reload = Database::from(db_path.clone()).open().unwrap();

    group.bench_function(BenchmarkId::from_parameter("no_auto_reload"), |b| {
        b.iter(|| {
            black_box(db_no_reload.lookup("threat42.com").unwrap());
        });
    });

    // Benchmark WITH auto-reload (lock-free Arc access)
    let db_with_reload = Database::from(db_path.clone())
        .auto_reload()
        .open()
        .unwrap();

    group.bench_function(BenchmarkId::from_parameter("with_auto_reload"), |b| {
        b.iter(|| {
            black_box(db_with_reload.lookup("threat42.com").unwrap());
        });
    });

    group.finish();
}

fn bench_concurrent_access(c: &mut Criterion) {
    use std::sync::Arc;
    use std::thread;

    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("concurrent.mxy");
    create_test_database(&db_path);

    let mut group = c.benchmark_group("concurrent_access");

    // Test with 4 threads hammering queries
    let db = Arc::new(
        Database::from(db_path.clone())
            .auto_reload()
            .open()
            .unwrap(),
    );

    group.bench_function("4_threads_auto_reload", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..4)
                .map(|tid| {
                    let db_clone = Arc::clone(&db);
                    thread::spawn(move || {
                        for i in 0..100 {
                            let query = format!("threat{}.com", (tid * 100 + i) % 1000);
                            black_box(db_clone.lookup(&query).unwrap());
                        }
                    })
                })
                .collect();

            for h in handles {
                h.join().unwrap();
            }
        });
    });

    group.finish();
}

criterion_group!(benches, bench_reload_overhead, bench_concurrent_access);
criterion_main!(benches);
