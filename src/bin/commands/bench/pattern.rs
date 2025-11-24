use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use crate::cli_utils::{format_bytes, format_number, format_qps};

#[allow(clippy::too_many_arguments)]
pub fn bench_pattern_database(
    count: usize,
    temp_file: &PathBuf,
    keep: bool,
    load_iterations: usize,
    query_count: usize,
    hit_rate: usize,
    cache_size: usize,
    cache_hit_rate: usize,
    pattern_style: &str,
) -> Result<()> {
    use matchy::mmdb_builder::MmdbBuilder;
    use matchy::Database;
    use matchy::MatchMode;

    println!("--- Phase 1: Build Pattern Database ---");
    let build_start = Instant::now();
    let mut builder = MmdbBuilder::new(MatchMode::CaseSensitive)
        .with_database_type("Benchmark-Pattern")
        .with_description("en", "Pattern database benchmark");

    let empty_data = HashMap::new();

    // Pattern generation based on style
    let tlds = [
        "com", "net", "org", "ru", "cn", "xyz", "tk", "info", "io", "cc",
    ];
    let malicious_words = [
        "malware", "phishing", "trojan", "evil", "attack", "botnet", "spam", "scam", "fake",
        "virus",
    ];
    let domains = [
        "domain", "site", "server", "host", "web", "portal", "service", "cloud", "zone", "network",
    ];

    for i in 0..count {
        // Generate patterns based on the requested style
        let pattern = match pattern_style {
            "prefix" => {
                // Pure prefix patterns: "prefix-*"
                let word = malicious_words[i % malicious_words.len()];
                let domain_word = domains[(i / 7) % domains.len()];
                let tld = tlds[i % tlds.len()];
                match i % 4 {
                    0 => format!("{}-{}-*", word, domain_word),
                    1 => format!("{}-{}-{}-*", word, domain_word, i % 1000),
                    2 => format!("threat-{}-*.{}", domain_word, tld),
                    _ => format!("{}{}-*", word, i % 1000),
                }
            }
            "suffix" => {
                // Pure suffix patterns: "*.domain.com"
                let word = malicious_words[i % malicious_words.len()];
                let domain_word = domains[(i / 7) % domains.len()];
                let tld = tlds[i % tlds.len()];
                match i % 4 {
                    0 => format!("*.{}-{}-{}.{}", word, domain_word, i, tld),
                    1 => format!("*.{}{}.{}", domain_word, i, tld),
                    2 => format!("*.{}-threat.{}", word, tld),
                    _ => format!("*.evil-{}.{}", i % 1000, tld),
                }
            }
            "mixed" => {
                // 50% prefix, 50% suffix
                let word = malicious_words[i % malicious_words.len()];
                let domain_word = domains[(i / 7) % domains.len()];
                let tld = tlds[i % tlds.len()];
                if i % 2 == 0 {
                    // Prefix
                    format!("{}-{}-*", word, domain_word)
                } else {
                    // Suffix
                    format!("*.{}-{}.{}", word, domain_word, tld)
                }
            }
            _ => {
                // "complex" - original complex patterns with multiple wildcards
                if i % 20 == 0 {
                    // ~5% complex patterns (multiple wildcards, character classes)
                    let word = malicious_words[i % malicious_words.len()];
                    let tld = tlds[(i / 20) % tlds.len()];
                    match (i / 20) % 4 {
                        0 => format!("*[0-9].*.{}-attack-{}.{}", word, i, tld),
                        1 => format!("{}-*-server[0-9][0-9].evil-{}.{}", word, i, tld),
                        2 => format!("*.{}-campaign-*-{}.{}", word, i, tld),
                        _ => format!("*bad*.{}-?.infection-{}.{}", word, i, tld),
                    }
                } else {
                    // 95% simpler but still diverse patterns
                    let word = malicious_words[i % malicious_words.len()];
                    let domain_word = domains[(i / 7) % domains.len()];
                    let tld = tlds[i % tlds.len()];

                    match i % 8 {
                        0 => format!("*.{}-{}-{}.{}", word, domain_word, i, tld),
                        1 => format!("{}-{}*.bad-{}.{}", word, domain_word, i, tld),
                        2 => format!("evil-{}-*.tracker-{}.{}", domain_word, i, tld),
                        3 => format!("*-{}-{}.threat{}.{}", word, domain_word, i, tld),
                        4 => format!("suspicious-*.{}-zone-{}.{}", domain_word, i, tld),
                        5 => format!("*.{}{}.{}-network.{}", word, i, domain_word, tld),
                        6 => format!("bad-{}-{}.*.{}", word, i, tld),
                        _ => format!("{}-threat-*.{}{}.{}", word, domain_word, i, tld),
                    }
                }
            }
        };
        builder.add_glob(&pattern, empty_data.clone())?;

        if count > 10_000 && (i + 1) % 10_000 == 0 {
            println!(
                "  Progress: {}/{}",
                format_number(i + 1),
                format_number(count)
            );
        }
    }

    let db_bytes = builder.build()?;
    let build_time = build_start.elapsed();
    let build_rate = count as f64 / build_time.as_secs_f64();

    println!("  Build time:  {:.2}s", build_time.as_secs_f64());
    println!("  Build rate:  {} patterns/sec", format_qps(build_rate));
    println!("  DB size:     {}", format_bytes(db_bytes.len()));
    println!();

    println!("--- Phase 2: Save to Disk ---");
    let save_start = Instant::now();
    std::fs::write(temp_file, &db_bytes)?;
    let save_time = save_start.elapsed();
    println!("  Save time:   {:.2}s", save_time.as_secs_f64());
    drop(db_bytes);
    println!();

    println!("--- Phase 3: Load Database (mmap) ---");
    let mut load_times = Vec::new();
    for i in 1..=load_iterations {
        let load_start = Instant::now();
        let _db = Database::from(temp_file.to_str().unwrap()).open()?;
        let load_time = load_start.elapsed();
        load_times.push(load_time);
        println!(
            "  Load #{}: {:.3}ms",
            i,
            load_time.as_micros() as f64 / 1000.0
        );
    }
    let avg_load = load_times.iter().sum::<std::time::Duration>() / load_iterations as u32;
    println!("  Average:  {:.3}ms", avg_load.as_micros() as f64 / 1000.0);
    println!();

    println!("--- Phase 4: Query Performance ---");
    let mut opener = Database::from(temp_file.to_str().unwrap());
    if cache_size == 0 {
        opener = opener.no_cache();
    } else {
        opener = opener.cache_capacity(cache_size);
    }
    let db = opener.open()?;
    let bench_start = Instant::now();
    let mut found = 0;

    let tlds = [
        "com", "net", "org", "ru", "cn", "xyz", "tk", "info", "io", "cc",
    ];
    let malicious_words = [
        "malware", "phishing", "trojan", "evil", "attack", "botnet", "spam", "scam", "fake",
        "virus",
    ];
    let domains = [
        "domain", "site", "server", "host", "web", "portal", "service", "cloud", "zone", "network",
    ];

    // Generate a pool of queries for cache simulation
    let unique_query_count = if cache_hit_rate == 0 {
        query_count // All unique queries (worst case)
    } else {
        // Calculate how many unique queries we need to achieve target cache hit rate
        // If cache_hit_rate is 80%, we want 20% unique queries
        let unique_pct = 100 - cache_hit_rate;
        (query_count * unique_pct / 100).max(1)
    };

    for i in 0..query_count {
        // Map query index to a unique query ID (for cache hit simulation)
        let query_id = i % unique_query_count;

        // Determine if this query should hit (match) based on hit_rate
        let should_hit = (query_id * 100 / unique_query_count) < hit_rate;

        let test_str = if !should_hit {
            // Generate non-matching query (benign traffic)
            format!("benign-clean-traffic-{}.legitimate-site.com", query_id)
        } else {
            // Generate matching query based on pattern_id and style
            let pattern_id = (query_id * 43) % count;
            let word = malicious_words[pattern_id % malicious_words.len()];
            let domain_word = domains[(pattern_id / 7) % domains.len()];
            let tld = tlds[pattern_id % tlds.len()];

            match pattern_style {
                "prefix" => {
                    // Match prefix patterns
                    match pattern_id % 4 {
                        0 => format!("{}-{}-suffix-{}", word, domain_word, i),
                        1 => format!("{}-{}-{}-end", word, domain_word, pattern_id % 1000),
                        2 => format!("threat-{}-middle.{}", domain_word, tld),
                        _ => format!("{}{}-anything", word, pattern_id % 1000),
                    }
                }
                "suffix" => {
                    // Match suffix patterns
                    match pattern_id % 4 {
                        0 => format!("prefix.{}-{}-{}.{}", word, domain_word, pattern_id, tld),
                        1 => format!("subdomain.{}{}.{}", domain_word, pattern_id, tld),
                        2 => format!("any.{}-threat.{}", word, tld),
                        _ => format!("prefix.evil-{}.{}", pattern_id % 1000, tld),
                    }
                }
                "mixed" => {
                    // Match mixed patterns
                    if pattern_id.is_multiple_of(2) {
                        // Prefix pattern match
                        format!("{}-{}-suffix", word, domain_word)
                    } else {
                        // Suffix pattern match
                        format!("prefix.{}-{}.{}", word, domain_word, tld)
                    }
                }
                _ => {
                    // "complex" - match original complex patterns
                    if pattern_id.is_multiple_of(20) {
                        // Match complex patterns (~5%)
                        match (pattern_id / 20) % 4 {
                            0 => format!("prefix5.middle.{}-attack-{}.{}", word, pattern_id, tld),
                            1 => format!("{}-middle-server99.evil-{}.{}", word, pattern_id, tld),
                            2 => format!("prefix.{}-campaign-middle-{}.{}", word, pattern_id, tld),
                            _ => format!(
                                "firstbadsecond.{}-x.infection-{}.{}",
                                word, pattern_id, tld
                            ),
                        }
                    } else {
                        // Match simpler patterns (95%)
                        match pattern_id % 8 {
                            0 => format!("prefix.{}-{}-{}.{}", word, domain_word, pattern_id, tld),
                            1 => {
                                format!("{}-{}middle.bad-{}.{}", word, domain_word, pattern_id, tld)
                            }
                            2 => format!(
                                "evil-{}-middle.tracker-{}.{}",
                                domain_word, pattern_id, tld
                            ),
                            3 => format!(
                                "prefix-{}-{}.threat{}.{}",
                                word, domain_word, pattern_id, tld
                            ),
                            4 => format!(
                                "suspicious-middle.{}-zone-{}.{}",
                                domain_word, pattern_id, tld
                            ),
                            5 => format!(
                                "prefix.{}{}.{}-network.{}",
                                word, pattern_id, domain_word, tld
                            ),
                            6 => format!("bad-{}-{}.middle.{}", word, pattern_id, tld),
                            _ => format!(
                                "{}-threat-middle.{}{}.{}",
                                word, domain_word, pattern_id, tld
                            ),
                        }
                    }
                }
            }
        };

        if let Some(matchy::QueryResult::Pattern { pattern_ids, .. }) = db.lookup(&test_str)? {
            if !pattern_ids.is_empty() {
                found += 1;
            }
        }
    }

    let bench_time = bench_start.elapsed();
    let qps = query_count as f64 / bench_time.as_secs_f64();
    let avg_query = bench_time / query_count as u32;

    println!("  Query count: {}", format_number(query_count));
    println!("  Total time:  {:.2}s", bench_time.as_secs_f64());
    println!("  QPS:         {} queries/sec", format_qps(qps));
    println!(
        "  Avg latency: {:.2}µs",
        avg_query.as_nanos() as f64 / 1000.0
    );
    println!(
        "  Found:       {}/{}",
        format_number(found),
        format_number(query_count)
    );
    println!();

    if !keep {
        std::fs::remove_file(temp_file)?;
        println!("✓ Benchmark complete (temp file removed)");
    } else {
        println!("✓ Benchmark complete (file kept: {})", temp_file.display());
    }

    Ok(())
}
