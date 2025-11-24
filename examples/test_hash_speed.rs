use matchy::literal_hash::LiteralHashBuilder;
use matchy::MatchMode;
use std::time::Instant;

fn main() {
    let count = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000);

    let patterns: Vec<String> = (0..count)
        .map(|i| format!("test_pattern_number_{}", i))
        .collect();

    println!("Testing hash table build with {} literals...", count);

    let start = Instant::now();

    let mut builder = LiteralHashBuilder::new(MatchMode::CaseSensitive);

    for (id, pattern) in patterns.iter().enumerate() {
        builder.add_pattern(pattern, id as u32);
    }

    let data_offsets: Vec<_> = (0..count).map(|i| (i, i * 100)).collect();
    let result = builder.build(&data_offsets).unwrap();

    let elapsed = start.elapsed();
    println!("Built hash table in: {:?}", elapsed);
    println!("Per pattern: {:?}", elapsed / count);
    println!("Table size: {} bytes", result.len());
}
