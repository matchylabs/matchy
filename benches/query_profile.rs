//! Query-only memory profiling
//!
//! This focuses on query-time allocations to verify zero-allocation matching.

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use matchy::bench_api::Paraglob;
use matchy::MatchMode;
use std::hint::black_box;

fn main() {
    // Build database BEFORE starting profiler
    let patterns = vec!["*.com", "*.org", "test*", "*suffix"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    println!("Database built, starting profiler...\n");

    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    // Now run queries - these should have ZERO allocations!
    for _ in 0..1_000_000 {
        let results = pg.find_all(black_box("test.com"));
        black_box(results);
    }

    println!("Completed 1,000,000 queries");

    #[cfg(feature = "dhat-heap")]
    {
        println!("\n=== Query-Only Memory Profile ==");
        println!("If allocations > 0, we have a problem!");
        println!("Results saved to: dhat-heap.json");
    }
}
