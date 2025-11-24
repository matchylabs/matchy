use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use matchy::bench_api::Paraglob;
use matchy::serialization::{load, save};
use matchy::MatchMode;
use std::hint::black_box;
use std::time::Duration;
use tempfile::NamedTempFile;

// Test data generators
fn generate_patterns(count: usize, pattern_type: &str) -> Vec<String> {
    match pattern_type {
        "literals" => (0..count).map(|i| format!("literal_{}", i)).collect(),
        "globs" => (0..count).map(|i| format!("*.ext{}", i)).collect(),
        "mixed" => (0..count)
            .map(|i| {
                if i % 3 == 0 {
                    format!("literal_{}", i)
                } else if i % 3 == 1 {
                    format!("*test_{}", i)
                } else {
                    format!("prefix_*_{}.txt", i)
                }
            })
            .collect(),
        "complex" => (0..count)
            .map(|i| format!("test_*_file_{}_*.txt", i))
            .collect(),
        _ => vec![],
    }
}

fn generate_text(size: usize, match_rate: &str) -> String {
    let words = [
        "hello",
        "world",
        "test",
        "file",
        "literal",
        "data",
        "sample",
        "benchmark",
    ];

    match match_rate {
        "none" => {
            // Text that won't match any patterns
            (0..size / 10)
                .map(|i| format!("nomatch{} ", i))
                .collect::<String>()
        }
        "low" => {
            // ~10% matches
            (0..size / 10)
                .map(|i| {
                    if i % 10 == 0 {
                        format!("literal_{} ", i % 100)
                    } else {
                        format!("nomatch{} ", i)
                    }
                })
                .collect::<String>()
        }
        "medium" => {
            // ~50% matches
            (0..size / 10)
                .map(|i| {
                    if i % 2 == 0 {
                        format!("literal_{} ", i % 100)
                    } else {
                        words[i % words.len()].to_string()
                    }
                })
                .collect::<String>()
        }
        "high" => {
            // ~90% matches
            (0..size / 10)
                .map(|i| format!("literal_{} ", i % 100))
                .collect::<String>()
        }
        _ => String::new(),
    }
}

// Benchmark 1: Build Performance
fn bench_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("build");

    for count in [10, 50, 100, 500, 1000].iter() {
        for pattern_type in ["literals", "globs", "mixed", "complex"].iter() {
            let patterns = generate_patterns(*count, pattern_type);
            let pattern_refs: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();

            group.throughput(Throughput::Elements(*count as u64));
            group.bench_with_input(
                BenchmarkId::new(*pattern_type, count),
                &pattern_refs,
                |b, patterns| {
                    b.iter(|| {
                        let pg = Paraglob::build_from_patterns(
                            black_box(patterns),
                            MatchMode::CaseSensitive,
                        )
                        .unwrap();
                        black_box(pg);
                    });
                },
            );
        }
    }

    group.finish();
}

// Benchmark 2: Match Performance
fn bench_match(c: &mut Criterion) {
    let mut group = c.benchmark_group("match");

    // Pre-build matchers of various sizes
    let pattern_counts = [10, 100, 1000];
    let text_sizes = [100, 1000, 10000];

    for &pattern_count in &pattern_counts {
        let patterns = generate_patterns(pattern_count, "mixed");
        let pattern_refs: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();
        let pg = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseSensitive).unwrap();

        for &text_size in &text_sizes {
            for match_rate in ["none", "low", "medium", "high"].iter() {
                let text = generate_text(text_size, match_rate);

                group.throughput(Throughput::Bytes(text.len() as u64));
                group.bench_with_input(
                    BenchmarkId::new(format!("p{}_t{}", pattern_count, text_size), match_rate),
                    &text,
                    |b, text| {
                        b.iter(|| {
                            let matches = pg.find_all(black_box(text));
                            black_box(matches);
                        });
                    },
                );
            }
        }
    }

    group.finish();
}

// Benchmark 3: Serialization Performance
fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization");

    for count in [10, 100, 1000].iter() {
        let patterns = generate_patterns(*count, "mixed");
        let pattern_refs: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();
        let pg = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseSensitive).unwrap();

        // Benchmark save
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(BenchmarkId::new("save", count), &pg, |b, pg| {
            b.iter(|| {
                let temp_file = NamedTempFile::new().unwrap();
                save(black_box(pg), temp_file.path()).unwrap();
                black_box(temp_file);
            });
        });
    }

    group.finish();
}

// Benchmark 4: Load Performance (The Star of the Show!)
fn bench_load(c: &mut Criterion) {
    let mut group = c.benchmark_group("load");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(100);

    for count in [10, 100, 1000, 5000].iter() {
        let patterns = generate_patterns(*count, "mixed");
        let pattern_refs: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();
        let pg = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseSensitive).unwrap();

        // Create a temp file
        let temp_file = NamedTempFile::new().unwrap();
        save(&pg, temp_file.path()).unwrap();

        let file_size = std::fs::metadata(temp_file.path()).unwrap().len();

        group.throughput(Throughput::Bytes(file_size));
        group.bench_with_input(
            BenchmarkId::new("mmap_load", count),
            temp_file.path(),
            |b, path| {
                b.iter(|| {
                    let loaded = load(black_box(path), MatchMode::CaseSensitive).unwrap();
                    black_box(loaded);
                });
            },
        );
    }

    group.finish();
}

// Benchmark 5: Memory Efficiency (File size vs pattern count)
fn bench_memory_efficiency(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_efficiency");

    for count in [10, 50, 100, 500, 1000].iter() {
        let patterns = generate_patterns(*count, "mixed");
        let pattern_refs: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();

        group.bench_with_input(
            BenchmarkId::new("file_size", count),
            &pattern_refs,
            |b, patterns| {
                b.iter(|| {
                    let pg = Paraglob::build_from_patterns(
                        black_box(patterns),
                        MatchMode::CaseSensitive,
                    )
                    .unwrap();

                    let temp_file = NamedTempFile::new().unwrap();
                    save(&pg, temp_file.path()).unwrap();

                    let file_size = std::fs::metadata(temp_file.path()).unwrap().len();
                    black_box(file_size);
                });
            },
        );
    }

    group.finish();
}

// Benchmark 6: Real-world scenario - Pattern database with frequent queries
fn bench_realistic_workload(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_workload");

    // Simulate a typical production scenario:
    // - 500 patterns (mix of literals and globs)
    // - Processing 100 strings of varying sizes
    let patterns = generate_patterns(500, "mixed");
    let pattern_refs: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();
    let pg = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseSensitive).unwrap();

    let test_strings: Vec<String> = (0..100)
        .map(|i| generate_text(100 + i * 10, if i % 4 == 0 { "high" } else { "low" }))
        .collect();

    group.throughput(Throughput::Elements(100));
    group.bench_function("process_batch", |b| {
        b.iter(|| {
            for text in &test_strings {
                let matches = pg.find_all(black_box(text));
                black_box(matches);
            }
        });
    });

    group.finish();
}

// Benchmark 7: Case sensitivity impact
fn bench_case_sensitivity(c: &mut Criterion) {
    let mut group = c.benchmark_group("case_sensitivity");

    let patterns = generate_patterns(100, "literals");
    let pattern_refs: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();

    let text = generate_text(1000, "medium");

    // Case sensitive
    let pg_sensitive =
        Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseSensitive).unwrap();

    group.bench_function("sensitive", |b| {
        b.iter(|| {
            let matches = pg_sensitive.find_all(black_box(&text));
            black_box(matches);
        });
    });

    // Case insensitive
    let pg_insensitive =
        Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseInsensitive).unwrap();

    group.bench_function("insensitive", |b| {
        b.iter(|| {
            let matches = pg_insensitive.find_all(black_box(&text));
            black_box(matches);
        });
    });

    group.finish();
}

// Benchmark 8: Dense Node Performance (tests 64-byte alignment impact)
fn bench_dense_nodes(c: &mut Criterion) {
    let mut group = c.benchmark_group("dense_nodes");

    // Create patterns that force dense nodes (9+ transitions)
    let mut patterns = Vec::new();

    // 26 patterns with common prefix -> creates dense node
    for ch in 'a'..='z' {
        patterns.push(format!("prefix_{}suffix", ch));
    }

    // 100 numeric patterns -> more dense nodes
    for i in 0..10 {
        for j in 0..10 {
            patterns.push(format!("num_{}{}_end", i, j));
        }
    }

    let pattern_refs: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();
    let pg = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseSensitive).unwrap();

    // Test traversing dense nodes
    let test_strings = vec!["prefix_msuffix", "num_55_end", "prefix_zsuffix"];

    group.bench_function("dense_lookup", |b| {
        b.iter(|| {
            for s in &test_strings {
                let matches = pg.find_all(black_box(s));
                black_box(matches);
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_build,
    bench_match,
    bench_serialization,
    bench_load,
    bench_memory_efficiency,
    bench_realistic_workload,
    bench_case_sensitivity,
    bench_dense_nodes
);

criterion_main!(benches);
