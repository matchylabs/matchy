//! Profile AC automaton for cache miss analysis
//!
//! Usage with Instruments (macOS):
//! 1. Build: `cargo build --release --example profile_ac`
//! 2. Profile: `instruments -t "System Trace" target/release/examples/profile_ac`
//! 3. Or use Xcode Instruments GUI: File > Open > select binary
//!
//! Usage with simple timing:
//! `cargo run --release --example profile_ac`

use matchy::ac_offset::{ACAutomaton, MatchMode};
use std::time::Instant;

fn main() {
    println!("=== AC Automaton Cache Profiling ===\n");

    // Test configurations matching realistic workloads
    let configs = vec![
        ("Small", 100, 1000, "high"),
        ("Medium", 500, 5000, "medium"),
        ("Large", 1000, 10000, "high"),
        ("XLarge", 5000, 10000, "low"),
    ];

    for (name, pattern_count, text_size, match_rate) in configs {
        println!("--- {} Workload ---", name);
        println!(
            "Patterns: {}, Text: {} bytes, Match rate: {}",
            pattern_count, text_size, match_rate
        );

        // Build automaton
        let patterns: Vec<String> = (0..pattern_count)
            .map(|i| format!("pattern_{}", i))
            .collect();
        let pattern_refs: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();

        let build_start = Instant::now();
        let ac = ACAutomaton::build(&pattern_refs, MatchMode::CaseSensitive)
            .expect("Failed to build AC automaton");
        let build_time = build_start.elapsed();
        println!("  Build time: {:?}", build_time);

        // Generate text
        let text = generate_text(text_size, match_rate, pattern_count);

        // Warm-up run
        let _ = ac.find_pattern_ids(&text);

        // Profiling run - do many iterations to get good data
        let iterations = 1000;
        let start = Instant::now();

        for _ in 0..iterations {
            let results = ac.find_pattern_ids(&text);
            // Use results to prevent optimization
            std::hint::black_box(results);
        }

        let elapsed = start.elapsed();
        let avg_time = elapsed / iterations;
        let throughput = (text.len() as f64 * iterations as f64) / elapsed.as_secs_f64()
            / 1024.0
            / 1024.0;

        println!("  Iterations: {}", iterations);
        println!("  Total time: {:?}", elapsed);
        println!("  Avg per query: {:?}", avg_time);
        println!("  Throughput: {:.2} MiB/s", throughput);
        println!();
    }

    println!("=== Profiling Complete ===");
    println!("\nTo see cache statistics on macOS:");
    println!("1. Run with Instruments System Trace");
    println!("2. Look at 'Memory' section for cache miss rates");
    println!("3. Or use: instruments -t 'Allocations' target/release/examples/profile_ac");
}

fn generate_text(size: usize, match_rate: &str, pattern_count: usize) -> String {
    match match_rate {
        "none" => {
            // Text that won't match
            (0..size / 10)
                .map(|i| format!("nomatch{} ", i))
                .collect()
        }
        "low" => {
            // ~10% matches
            (0..size / 10)
                .map(|i| {
                    if i % 10 == 0 {
                        format!("pattern_{} ", i % pattern_count)
                    } else {
                        format!("nomatch{} ", i)
                    }
                })
                .collect()
        }
        "medium" => {
            // ~50% matches
            (0..size / 10)
                .map(|i| {
                    if i % 2 == 0 {
                        format!("pattern_{} ", i % pattern_count)
                    } else {
                        format!("word{} ", i)
                    }
                })
                .collect()
        }
        "high" => {
            // ~90% matches
            (0..size / 10)
                .map(|i| format!("pattern_{} ", i % pattern_count))
                .collect()
        }
        _ => String::new(),
    }
}
