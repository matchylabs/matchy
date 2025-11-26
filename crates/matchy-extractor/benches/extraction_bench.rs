use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use matchy_extractor::ExtractorBuilder;
use std::hint::black_box;

fn generate_text_with_domains(size: usize, domain_density: &str) -> String {
    let domains = [
        "evil.example.com",
        "malware.co.uk",
        "phishing.org",
        "threat.gov.uk",
        "badsite.com.au",
        "suspicious.net",
        "attacker.io",
        "command.cc",
    ];

    let filler_words = vec![
        "the",
        "quick",
        "brown",
        "fox",
        "jumps",
        "over",
        "lazy",
        "dog",
        "hello",
        "world",
        "test",
        "data",
        "sample",
        "benchmark",
        "performance",
    ];

    let mut text = String::new();
    let mut word_count = 0;

    match domain_density {
        "none" => {
            // No domains at all
            while text.len() < size {
                text.push_str(filler_words[word_count % filler_words.len()]);
                text.push(' ');
                word_count += 1;
            }
        }
        "low" => {
            // ~5% domains
            while text.len() < size {
                if word_count % 20 == 0 {
                    text.push_str(domains[word_count % domains.len()]);
                } else {
                    text.push_str(filler_words[word_count % filler_words.len()]);
                }
                text.push(' ');
                word_count += 1;
            }
        }
        "medium" => {
            // ~25% domains
            while text.len() < size {
                if word_count % 4 == 0 {
                    text.push_str(domains[word_count % domains.len()]);
                } else {
                    text.push_str(filler_words[word_count % filler_words.len()]);
                }
                text.push(' ');
                word_count += 1;
            }
        }
        "high" => {
            // ~50% domains
            while text.len() < size {
                if word_count % 2 == 0 {
                    text.push_str(domains[word_count % domains.len()]);
                } else {
                    text.push_str(filler_words[word_count % filler_words.len()]);
                }
                text.push(' ');
                word_count += 1;
            }
        }
        _ => {}
    }

    text.truncate(size);
    text
}

fn bench_domain_extraction(c: &mut Criterion) {
    let mut group = c.benchmark_group("domain_extraction");

    // Build extractor with only domain extraction enabled (to isolate performance)
    let extractor = ExtractorBuilder::new()
        .extract_domains(true)
        .extract_emails(false)
        .extract_ipv4(false)
        .extract_ipv6(false)
        .extract_hashes(false)
        .extract_bitcoin(false)
        .extract_ethereum(false)
        .extract_monero(false)
        .build()
        .unwrap();

    let text_sizes = vec![1_000, 10_000, 100_000];
    let densities = vec!["none", "low", "medium", "high"];

    for &size in &text_sizes {
        for density in &densities {
            let text = generate_text_with_domains(size, density);
            let text_bytes = text.as_bytes();

            group.throughput(Throughput::Bytes(text_bytes.len() as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("size_{}", size), density),
                &text_bytes,
                |b, bytes| {
                    b.iter(|| {
                        let matches = extractor.extract_from_chunk(black_box(bytes));
                        black_box(matches);
                    });
                },
            );
        }
    }

    group.finish();
}

fn bench_realistic_log_data(c: &mut Criterion) {
    let mut group = c.benchmark_group("domain_extraction_realistic");

    let extractor = ExtractorBuilder::new()
        .extract_domains(true)
        .extract_emails(false)
        .extract_ipv4(false)
        .extract_ipv6(false)
        .extract_hashes(false)
        .extract_bitcoin(false)
        .extract_ethereum(false)
        .extract_monero(false)
        .build()
        .unwrap();

    // Realistic log line with domain
    let log_lines = [
        b"2024-11-20 10:23:45 [INFO] HTTP request to evil.example.com from 192.168.1.100"
            .as_slice(),
        b"2024-11-20 10:23:46 [WARN] DNS query for malware.co.uk blocked by firewall".as_slice(),
        b"2024-11-20 10:23:47 [ERROR] Connection to phishing.org timeout after 30s".as_slice(),
        b"2024-11-20 10:23:48 [INFO] Processing file data.json (size: 1024 bytes)".as_slice(),
        b"2024-11-20 10:23:49 [DEBUG] Cache hit for key=user:12345 value=active".as_slice(),
    ];

    // Concatenate into larger chunk
    let chunk: Vec<u8> = log_lines
        .iter()
        .cycle()
        .take(1000)
        .flat_map(|line| line.iter().copied().chain(b"\n".iter().copied()))
        .collect();

    group.throughput(Throughput::Bytes(chunk.len() as u64));
    group.bench_function("log_lines_1000", |b| {
        b.iter(|| {
            let matches = extractor.extract_from_chunk(black_box(&chunk));
            black_box(matches);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_domain_extraction, bench_realistic_log_data);
criterion_main!(benches);
