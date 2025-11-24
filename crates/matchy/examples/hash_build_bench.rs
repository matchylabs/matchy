//! Benchmark for parallel hash table building
//!
//! This example demonstrates the performance of parallel sharded hash table construction
//! compared to a single-threaded build.

use matchy::literal_hash::LiteralHashBuilder;
use matchy::MatchMode;
use std::time::Instant;

fn main() {
    // Test with different sizes
    for size in [1_000, 10_000, 100_000, 1_000_000] {
        println!("\n=== Building hash table with {} patterns ===", size);

        let mut builder = LiteralHashBuilder::new(MatchMode::CaseSensitive);
        for i in 0..size {
            let pattern = format!("pattern_{}_test", i);
            builder.add_pattern(&pattern, i);
        }

        let pattern_data: Vec<_> = (0..size).map(|i| (i, i * 100)).collect();

        let start = Instant::now();
        let bytes = builder.build(&pattern_data).expect("Build failed");
        let elapsed = start.elapsed();

        println!("  Build time: {:?}", elapsed);
        println!("  Database size: {} MB", bytes.len() / 1_048_576);
        println!(
            "  Throughput: {:.0} patterns/sec",
            size as f64 / elapsed.as_secs_f64()
        );
    }
}
