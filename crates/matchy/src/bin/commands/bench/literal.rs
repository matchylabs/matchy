use anyhow::Result;
use std::collections::HashMap;
use std::time::Instant;

use crate::cli_utils::{format_bytes, format_number, format_qps};
use crate::commands::bench::BenchConfig;

pub fn bench_literal_database(config: BenchConfig) -> Result<()> {
    let BenchConfig {
        count,
        temp_file,
        keep,
        load_iterations,
        query_count,
        hit_rate,
        cache_size,
        cache_hit_rate,
    } = config;
    use matchy::mmdb_builder::MmdbBuilder;
    use matchy::Database;
    use matchy::MatchMode;

    println!("--- Phase 1: Build Literal Database ---");
    let build_start = Instant::now();
    let mut builder = MmdbBuilder::new(MatchMode::CaseSensitive)
        .with_database_type("Benchmark-Literal")
        .with_description("en", "Literal database benchmark");

    let empty_data = HashMap::new();

    // Generate realistic literal strings (domains, URLs, file paths, identifiers)
    let tlds = [
        "com", "net", "org", "io", "co", "dev", "app", "tech", "xyz", "cloud",
    ];
    let categories = [
        "api", "cdn", "web", "mail", "ftp", "vpn", "db", "auth", "admin", "test",
    ];
    let services = [
        "service", "server", "endpoint", "gateway", "proxy", "router", "node", "host", "instance",
        "cluster",
    ];

    for i in 0..count {
        // Generate varied literal patterns without wildcards
        let literal = match i % 10 {
            0 => {
                // Domain-style literals
                let cat = categories[i % categories.len()];
                let svc = services[(i / 10) % services.len()];
                let tld = tlds[i % tlds.len()];
                format!("{}-{}-{}.example.{}", cat, svc, i, tld)
            }
            1 => {
                // URL path literals
                let cat = categories[i % categories.len()];
                format!("/api/v2/{}/endpoint/{}/resource", cat, i)
            }
            2 => {
                // File path literals
                let svc = services[i % services.len()];
                format!("/var/log/{}/application-{}.log", svc, i)
            }
            3 => {
                // Email-style literals
                let cat = categories[i % categories.len()];
                let tld = tlds[i % tlds.len()];
                format!("{}user{}@domain{}.{}", cat, i, i % 100, tld)
            }
            4 => {
                // UUID-style literals
                format!(
                    "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
                    i,
                    (i >> 16) & 0xFFFF,
                    (i >> 8) & 0xFFFF,
                    i & 0xFFFF,
                    i * 1000
                )
            }
            5 => {
                // Database table.column literals
                let cat = categories[i % categories.len()];
                let svc = services[i % services.len()];
                format!("{}_table_{}.{}_column", cat, i, svc)
            }
            6 => {
                // API key style literals
                format!("sk_live_{:016x}_{:016x}", i, i * 7)
            }
            7 => {
                // Container/image literals
                let cat = categories[i % categories.len()];
                format!(
                    "docker.io/myorg/{}-image:v{}.{}.{}",
                    cat,
                    i / 100,
                    i % 10,
                    i % 5
                )
            }
            8 => {
                // Git branch/tag literals
                let cat = categories[i % categories.len()];
                format!("feature/{}-implementation-{}", cat, i)
            }
            _ => {
                // Simple identifier literals
                let cat = categories[i % categories.len()];
                let svc = services[i % services.len()];
                format!("{}_{}_{}", cat, svc, i)
            }
        };
        builder.add_literal(&literal, empty_data.clone())?;

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
    println!("  Build rate:  {} literals/sec", format_qps(build_rate));
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

    // Calculate unique query count to achieve target cache hit rate
    let unique_queries = if cache_hit_rate >= 100 {
        1 // All queries hit same entry
    } else if cache_hit_rate == 0 {
        query_count // Every query unique
    } else {
        let unique = query_count * (100 - cache_hit_rate) / 100;
        unique.max(1)
    };

    let bench_start = Instant::now();
    let mut found = 0;

    let tlds = [
        "com", "net", "org", "io", "co", "dev", "app", "tech", "xyz", "cloud",
    ];
    let categories = [
        "api", "cdn", "web", "mail", "ftp", "vpn", "db", "auth", "admin", "test",
    ];
    let services = [
        "service", "server", "endpoint", "gateway", "proxy", "router", "node", "host", "instance",
        "cluster",
    ];

    for i in 0..query_count {
        // Use modulo to cycle through a limited pool of queries for cache hits
        let query_idx = i % unique_queries;

        // Determine if this query should hit (match) based on hit_rate
        let should_hit = (query_idx * 100 / unique_queries) < hit_rate;

        let test_str = if !should_hit {
            // Generate non-matching query
            format!("nomatch-query-string-{}", query_idx)
        } else {
            // Generate matching query - must exactly match one of the patterns
            let pattern_id = (query_idx * 43) % count;

            match pattern_id % 10 {
                0 => {
                    let cat = categories[pattern_id % categories.len()];
                    let svc = services[(pattern_id / 10) % services.len()];
                    let tld = tlds[pattern_id % tlds.len()];
                    format!("{}-{}-{}.example.{}", cat, svc, pattern_id, tld)
                }
                1 => {
                    let cat = categories[pattern_id % categories.len()];
                    format!("/api/v2/{}/endpoint/{}/resource", cat, pattern_id)
                }
                2 => {
                    let svc = services[pattern_id % services.len()];
                    format!("/var/log/{}/application-{}.log", svc, pattern_id)
                }
                3 => {
                    let cat = categories[pattern_id % categories.len()];
                    let tld = tlds[pattern_id % tlds.len()];
                    format!(
                        "{}user{}@domain{}.{}",
                        cat,
                        pattern_id,
                        pattern_id % 100,
                        tld
                    )
                }
                4 => format!(
                    "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
                    pattern_id,
                    (pattern_id >> 16) & 0xFFFF,
                    (pattern_id >> 8) & 0xFFFF,
                    pattern_id & 0xFFFF,
                    pattern_id * 1000
                ),
                5 => {
                    let cat = categories[pattern_id % categories.len()];
                    let svc = services[pattern_id % services.len()];
                    format!("{}_table_{}.{}_column", cat, pattern_id, svc)
                }
                6 => format!("sk_live_{:016x}_{:016x}", pattern_id, pattern_id * 7),
                7 => {
                    let cat = categories[pattern_id % categories.len()];
                    format!(
                        "docker.io/myorg/{}-image:v{}.{}.{}",
                        cat,
                        pattern_id / 100,
                        pattern_id % 10,
                        pattern_id % 5
                    )
                }
                8 => {
                    let cat = categories[pattern_id % categories.len()];
                    format!("feature/{}-implementation-{}", cat, pattern_id)
                }
                _ => {
                    let cat = categories[pattern_id % categories.len()];
                    let svc = services[pattern_id % services.len()];
                    format!("{}_{}_{}", cat, svc, pattern_id)
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
