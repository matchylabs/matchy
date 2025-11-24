//! Demonstrates glob pattern matching capabilities.
//!
//! This example shows:
//! - Basic wildcard matching (*, ?)
//! - Character classes ([...], [!...])
//! - Case-sensitive and case-insensitive matching
//! - Performance characteristics

use matchy::glob::{GlobPattern, MatchMode};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🌟 Paraglob-rs Glob Pattern Demo\n");

    // 1. Basic Wildcards
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("1. Basic Wildcard Patterns");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    demo_pattern(
        "*.txt",
        &[
            ("file.txt", true),
            ("document.txt", true),
            ("readme.TXT", false),
            ("file.pdf", false),
        ],
        MatchMode::CaseSensitive,
    )?;

    demo_pattern(
        "file?.txt",
        &[
            ("file1.txt", true),
            ("fileA.txt", true),
            ("file.txt", false),
            ("file10.txt", false),
        ],
        MatchMode::CaseSensitive,
    )?;

    demo_pattern(
        "*hello*world*",
        &[
            ("hello world", true),
            ("say hello to the world", true),
            ("helloworld", true),
            ("hello", false),
        ],
        MatchMode::CaseSensitive,
    )?;

    // 2. Character Classes
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("2. Character Classes");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    demo_pattern(
        "file[0-9].txt",
        &[
            ("file0.txt", true),
            ("file5.txt", true),
            ("file9.txt", true),
            ("fileA.txt", false),
        ],
        MatchMode::CaseSensitive,
    )?;

    demo_pattern(
        "[a-zA-Z]*.txt",
        &[
            ("a.txt", true),
            ("Hello.txt", true),
            ("z123.txt", true),
            ("1file.txt", false),
        ],
        MatchMode::CaseSensitive,
    )?;

    demo_pattern(
        "file[!0-9].txt",
        &[
            ("fileA.txt", true),
            ("file_.txt", true),
            ("file0.txt", false),
            ("file9.txt", false),
        ],
        MatchMode::CaseSensitive,
    )?;

    // 3. Case Sensitivity
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("3. Case Sensitivity");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    println!("Pattern: \"*.TXT\" (Case-Sensitive)");
    demo_pattern(
        "*.TXT",
        &[
            ("file.TXT", true),
            ("FILE.TXT", true), // Star matches FILE as well
            ("file.txt", false),
        ],
        MatchMode::CaseSensitive,
    )?;

    println!("\nPattern: \"*.TXT\" (Case-Insensitive)");
    demo_pattern(
        "*.TXT",
        &[
            ("file.TXT", true),
            ("FILE.TXT", true),
            ("file.txt", true),
            ("file.pdf", false),
        ],
        MatchMode::CaseInsensitive,
    )?;

    // 4. Escape Sequences
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("4. Escape Sequences");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    demo_pattern(
        r"file\*.txt",
        &[
            ("file*.txt", true),
            ("file1.txt", false),
            ("fileany.txt", false),
        ],
        MatchMode::CaseSensitive,
    )?;

    demo_pattern(
        r"test\?.log",
        &[("test?.log", true), ("test1.log", false)],
        MatchMode::CaseSensitive,
    )?;

    // 5. Complex Patterns
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("5. Complex Patterns");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    demo_pattern(
        "**/test_*.rs",
        &[
            ("some/path/test_main.rs", true),
            ("//test_util.rs", true),     // Requires literal //
            ("src/test_helper.rs", true), // Star matches everything
        ],
        MatchMode::CaseSensitive,
    )?;

    demo_pattern(
        "[0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]",
        &[
            ("123-45-6789", true),
            ("000-00-0000", true),
            ("12-345-6789", false),
        ],
        MatchMode::CaseSensitive,
    )?;

    // 6. UTF-8 Support
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("6. UTF-8 Support");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    demo_pattern(
        "hello*",
        &[
            ("hello世界", true),
            ("hello🌍", true),
            ("hello", true),
            ("goodbye", false),
        ],
        MatchMode::CaseSensitive,
    )?;

    // 7. Performance Demo
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("7. Performance Characteristics");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    performance_demo()?;

    println!("\n✅ All demos completed successfully!\n");

    Ok(())
}

/// Demonstrates a single pattern with multiple test cases
fn demo_pattern(
    pattern_str: &str,
    tests: &[(&str, bool)],
    mode: MatchMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let pattern = GlobPattern::new(pattern_str, mode)?;

    println!("Pattern: \"{}\"", pattern_str);
    println!("Mode: {:?}", mode);
    println!("Segments: {:?}", pattern.segments());
    println!();

    let mut all_pass = true;
    for (text, expected) in tests {
        let result = pattern.matches(text);
        let status = if result == *expected {
            "✓"
        } else {
            all_pass = false;
            "✗"
        };
        println!(
            "  {} \"{}\" → {}",
            status,
            text,
            if result { "MATCH" } else { "no match" }
        );
    }

    if !all_pass {
        println!("\n⚠️  Some tests failed!");
    }
    println!();

    Ok(())
}

/// Demonstrates performance characteristics
fn performance_demo() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Instant;

    // Test pattern complexity
    let patterns = vec![
        ("Simple literal", "hello"),
        ("Single wildcard", "*.txt"),
        ("Multiple wildcards", "*hello*world*"),
        ("Character class", "file[0-9].txt"),
        ("Complex pattern", "**/[a-z][0-9]*_test.rs"),
    ];

    let test_strings = vec![
        "hello",
        "file.txt",
        "say hello to the world today",
        "file5.txt",
        "some/path/a1_test.rs",
    ];

    println!("Measuring pattern compilation time:\n");

    for (name, pattern_str) in &patterns {
        let start = Instant::now();
        let pattern = GlobPattern::new(pattern_str, MatchMode::CaseSensitive)?;
        let compile_time = start.elapsed();

        let start = Instant::now();
        let mut match_count = 0;
        for _ in 0..1000 {
            for text in &test_strings {
                if pattern.matches(text) {
                    match_count += 1;
                }
            }
        }
        let match_time = start.elapsed();

        println!("{}: \"{}\"", name, pattern_str);
        println!("  Compile: {:?}", compile_time);
        println!(
            "  5000 matches: {:?} ({:.2} µs/match)",
            match_time,
            match_time.as_micros() as f64 / 5000.0
        );
        println!("  Matches found: {}/5000", match_count);
        println!();
    }

    // Test text length scaling
    println!("Testing text length scaling (pattern \"*hello*world*\"):\n");

    let pattern = GlobPattern::new("*hello*world*", MatchMode::CaseSensitive)?;
    let base_text = "prefix hello middle world suffix";

    for multiplier in [1, 10, 100, 1000] {
        let text = base_text.repeat(multiplier);
        let start = Instant::now();

        for _ in 0..100 {
            let _ = pattern.matches(&text);
        }

        let elapsed = start.elapsed();
        println!("  Text length: {} bytes", text.len());
        println!(
            "    100 matches: {:?} ({:.2} µs/match)",
            elapsed,
            elapsed.as_micros() as f64 / 100.0
        );
    }

    Ok(())
}
