use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use crate::cli_utils::{format_bytes, format_number, format_qps};

pub fn bench_combined_database(
    count: usize,
    temp_file: &PathBuf,
    keep: bool,
    load_iterations: usize,
    query_count: usize,
    cache_size: usize,
    cache_hit_rate: usize,
) -> Result<()> {
    use matchy::mmdb_builder::DatabaseBuilder;
    use matchy::Database;
    use matchy::MatchMode;

    println!("--- Phase 1: Build Combined Database ---");
    let build_start = Instant::now();
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive)
        .with_database_type("Benchmark-Combined")
        .with_description("en", "Combined IP+Pattern benchmark");

    let empty_data = HashMap::new();

    // Add IPs (half the count)
    let ip_count = count / 2;
    for i in 0..ip_count {
        let ip_num = i as u32;
        let octet1 = (ip_num >> 24) & 0xFF;
        let octet2 = (ip_num >> 16) & 0xFF;
        let octet3 = (ip_num >> 8) & 0xFF;
        let octet4 = ip_num & 0xFF;
        let ip_str = format!("{}.{}.{}.{}", octet1, octet2, octet3, octet4);
        builder.add_ip(&ip_str, empty_data.clone())?;

        if ip_count > 100_000 && (i + 1) % 500_000 == 0 {
            println!(
                "  IP progress: {}/{}",
                format_number(i + 1),
                format_number(ip_count)
            );
        }
    }

    // Add patterns (other half)
    let pattern_count = count - ip_count;
    for i in 0..pattern_count {
        // Generate varied patterns with ~5% complex ones
        let pattern = if i % 20 == 0 {
            // ~5% complex patterns
            match (i / 20) % 4 {
                0 => format!("*[0-9].*.attacker{}.com", i),
                1 => format!("evil-*-[a-z][a-z].*.domain{}.net", i),
                2 => "*.malware-[0-9][0-9][0-9]-*.com".to_string(),
                _ => "*bad*.phishing-?.*.org".to_string(),
            }
        } else {
            match i % 4 {
                0 => format!("*.domain{}.com", i),
                1 => format!("subdomain{}.*.com", i),
                2 => format!("test-{}-*.com", i),
                _ => format!("*-{}.net", i),
            }
        };
        builder.add_glob(&pattern, empty_data.clone())?;

        if pattern_count > 10_000 && (i + 1) % 5_000 == 0 {
            println!(
                "  Pattern progress: {}/{}",
                format_number(i + 1),
                format_number(pattern_count)
            );
        }
    }

    let db_bytes = builder.build()?;
    let build_time = build_start.elapsed();
    let build_rate = count as f64 / build_time.as_secs_f64();

    println!("  Build time:  {:.2}s", build_time.as_secs_f64());
    println!("  Build rate:  {} entries/sec", format_qps(build_rate));
    println!("  DB size:     {}", format_bytes(db_bytes.len()));
    println!("  IPs:         {}", format_number(ip_count));
    println!("  Patterns:    {}", format_number(pattern_count));
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

    // Query both IPs and patterns
    let bench_start = Instant::now();
    let mut ip_found = 0;
    let mut pattern_found = 0;

    let half_queries = query_count / 2;
    let unique_half = unique_queries / 2;

    // Query IPs
    for i in 0..half_queries {
        let query_idx = i % unique_half.max(1);
        let ip_num = ((query_idx * 43) % ip_count) as u32;
        let octet1 = (ip_num >> 24) & 0xFF;
        let octet2 = (ip_num >> 16) & 0xFF;
        let octet3 = (ip_num >> 8) & 0xFF;
        let octet4 = ip_num & 0xFF;
        let ip = std::net::Ipv4Addr::new(octet1 as u8, octet2 as u8, octet3 as u8, octet4 as u8);

        if let Some(matchy::QueryResult::Ip { .. }) = db.lookup_ip(std::net::IpAddr::V4(ip))? {
            ip_found += 1;
        }
    }

    // Query patterns
    for i in 0..(query_count - half_queries) {
        let query_idx = i % unique_half.max(1);
        let pattern_id = (query_idx * 43) % pattern_count;
        let test_str = if pattern_id.is_multiple_of(20) {
            // Match complex patterns (~5%)
            match (pattern_id / 20) % 4 {
                0 => format!("prefix5.suffix.attacker{}.com", pattern_id),
                1 => format!("evil-middle-ab.end.domain{}.net", pattern_id),
                2 => "prefix.malware-123-suffix.com".to_string(),
                _ => "firstbadsecond.phishing-x.end.org".to_string(),
            }
        } else {
            match pattern_id % 4 {
                0 => format!("prefix.domain{}.com", pattern_id),
                1 => format!("subdomain{}.middle.com", pattern_id),
                2 => format!("test-{}-suffix.com", pattern_id),
                _ => format!("prefix-{}.net", pattern_id),
            }
        };

        if let Some(matchy::QueryResult::Pattern { pattern_ids, .. }) = db.lookup(&test_str)? {
            if !pattern_ids.is_empty() {
                pattern_found += 1;
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
        "  IP found:    {}/{}",
        format_number(ip_found),
        format_number(half_queries)
    );
    println!(
        "  Pattern found: {}/{}",
        format_number(pattern_found),
        format_number(query_count - half_queries)
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
