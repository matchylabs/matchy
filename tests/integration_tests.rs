//! Integration tests for Paraglob pattern matching correctness
//!
//! These tests verify end-to-end functionality of the pattern matcher
//! including edge cases, complex patterns, and real-world scenarios.

#![cfg(feature = "bench-internal")]

use matchy::bench_api::Paraglob;
use matchy::data_section::DataValue;
use matchy::serialization::{from_bytes, to_bytes};
use matchy::MatchMode;
use std::collections::HashMap;

#[test]
fn test_basic_wildcards() {
    let patterns = vec!["*.txt", "test*", "*file*"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("document.txt");
    let m2 = pg.find_all("test_case");
    let m3 = pg.find_all("myfile.dat");
    let m4 = pg.find_all("nomatch");

    assert!(!m1.is_empty(), "*.txt should match document.txt");
    assert!(!m2.is_empty(), "test* should match test_case");
    assert!(!m3.is_empty(), "*file* should match myfile.dat");
    assert!(m4.is_empty(), "nothing should match nomatch");
}

#[test]
fn test_exact_string_matching() {
    let patterns = vec!["hello", "world", "test"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("hello");
    let m2 = pg.find_all("world");
    let m3 = pg.find_all("hello world");
    let m4 = pg.find_all("nomatch");

    assert_eq!(m1.len(), 1, "hello should match exactly once");
    assert_eq!(m2.len(), 1, "world should match exactly once");
    assert_eq!(m3.len(), 2, "hello world should match both hello and world");
    assert!(m4.is_empty(), "nomatch should not match anything");
}

#[test]
fn test_duplicate_pattern_deduplication() {
    let patterns = vec!["*test*", "*test*", "hello", "hello"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("test123");
    let m2 = pg.find_all("hello");

    // Should deduplicate, so only 1 match each
    assert_eq!(
        m1.len(),
        1,
        "duplicate *test* patterns should be deduplicated"
    );
    assert_eq!(
        m2.len(),
        1,
        "duplicate hello patterns should be deduplicated"
    );
}

#[test]
fn test_multiple_patterns_matching_same_text() {
    let patterns = vec!["*.txt", "*file*", "test*"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("testfile.txt");

    // Should match all 3 patterns
    assert_eq!(m1.len(), 3, "testfile.txt should match all three patterns");
    assert!(m1.contains(&0), "should match *.txt");
    assert!(m1.contains(&1), "should match *file*");
    assert!(m1.contains(&2), "should match test*");
}

#[test]
fn test_case_sensitivity() {
    let patterns = vec!["Test*", "HELLO"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("Test123");
    let m2 = pg.find_all("test123");
    let m3 = pg.find_all("HELLO");
    let m4 = pg.find_all("hello");

    assert!(!m1.is_empty(), "Test* should match Test123");
    assert!(
        m2.is_empty(),
        "Test* should NOT match test123 (case sensitive)"
    );
    assert!(!m3.is_empty(), "HELLO should match HELLO");
    assert!(
        m4.is_empty(),
        "HELLO should NOT match hello (case sensitive)"
    );
}

#[test]
fn test_case_insensitivity() {
    let patterns = vec!["Test*", "HELLO"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseInsensitive).unwrap();

    let m1 = pg.find_all("Test123");
    let m2 = pg.find_all("test123");
    let m3 = pg.find_all("HELLO");
    let m4 = pg.find_all("hello");

    assert!(!m1.is_empty(), "Test* should match Test123");
    assert!(
        !m2.is_empty(),
        "Test* should match test123 (case insensitive)"
    );
    assert!(!m3.is_empty(), "HELLO should match HELLO");
    assert!(
        !m4.is_empty(),
        "HELLO should match hello (case insensitive)"
    );
}

#[test]
fn test_empty_string_queries() {
    let patterns = vec!["test"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("");
    let m2 = pg.find_all("test");

    assert!(m1.is_empty(), "empty string should not match anything");
    assert_eq!(m2.len(), 1, "test should match test pattern");
}

#[test]
fn test_pure_literal_patterns() {
    let patterns = vec!["exact_match", "another_literal", "third"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("exact_match");
    let m2 = pg.find_all("prefix_exact_match_suffix");
    let m3 = pg.find_all("nomatch");

    assert_eq!(m1.len(), 1, "exact_match should match exact_match pattern");
    assert_eq!(
        m2.len(),
        1,
        "prefix_exact_match_suffix should match exact_match pattern (substring)"
    );
    assert!(m3.is_empty(), "nomatch should not match anything");
}

#[test]
fn test_overlapping_literal_patterns() {
    let patterns = vec!["*test*", "test*", "*test"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("test");
    let m2 = pg.find_all("testing");
    let m3 = pg.find_all("mytest");
    let m4 = pg.find_all("mytesting");

    // All 3 patterns have "test" as literal
    assert_eq!(m1.len(), 3, "test should match all 3 patterns");
    assert_eq!(m2.len(), 2, "testing should match *test* and test*");
    assert_eq!(m3.len(), 2, "mytest should match *test* and *test");
    assert_eq!(m4.len(), 1, "mytesting should match only *test*");
}

#[test]
fn test_real_world_file_patterns() {
    let patterns = vec!["*.rs", "*.toml", "Cargo.*", "src/*", "*.md"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("main.rs");
    let m2 = pg.find_all("Cargo.toml");
    let m3 = pg.find_all("src/lib.rs");
    let m4 = pg.find_all("README.md");
    let m5 = pg.find_all("test.py");

    assert!(!m1.is_empty(), "main.rs should match *.rs");
    assert!(
        m2.len() >= 2,
        "Cargo.toml should match both *.toml and Cargo.*"
    );
    assert!(m3.len() >= 2, "src/lib.rs should match both *.rs and src/*");
    assert!(!m4.is_empty(), "README.md should match *.md");
    assert!(m5.is_empty(), "test.py should not match any pattern");
}

#[test]
fn test_large_pattern_set() {
    // Generate a large set of patterns to test scalability
    let mut patterns = Vec::new();
    for i in 0..1000 {
        patterns.push(format!("pattern_{}_*", i));
    }
    let pattern_refs: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();
    let pg = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseSensitive).unwrap();

    // Test that we can find specific patterns in the large set
    let m1 = pg.find_all("pattern_500_test");
    let m2 = pg.find_all("pattern_999_data");
    let m3 = pg.find_all("nomatch");

    // Note: These will match multiple patterns due to substring matching
    // "pattern_500_test" contains "pattern_5", "pattern_50", and "pattern_500"
    assert!(
        !m1.is_empty(),
        "pattern_500_test should match at least pattern_500_*"
    );
    assert!(
        !m2.is_empty(),
        "pattern_999_data should match at least pattern_999_*"
    );
    assert!(m3.is_empty(), "nomatch should not match anything");

    // Verify it includes the expected primary matches
    assert!(m1.contains(&500), "should match pattern_500_*");
    assert!(m2.contains(&999), "should match pattern_999_*");
}

#[test]
fn test_combined_literal_and_glob_patterns() {
    // Mix of literal strings and glob patterns
    let patterns = vec!["hello", "*.txt", "test_*"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("hello.txt");
    let m2 = pg.find_all("test_file.txt");

    // hello.txt should match both "hello" (substring) and "*.txt"
    assert_eq!(m1.len(), 2, "hello.txt should match hello and *.txt");
    assert!(m1.contains(&0), "should match hello");
    assert!(m1.contains(&1), "should match *.txt");

    // test_file.txt should match both "test_*" and "*.txt"
    assert_eq!(m2.len(), 2, "test_file.txt should match test_* and *.txt");
    assert!(m2.contains(&1), "should match *.txt");
    assert!(m2.contains(&2), "should match test_*");
}

#[test]
fn test_pure_wildcard_patterns() {
    let patterns = vec!["*", "?", "**"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("test");
    let m2 = pg.find_all("a");
    let m3 = pg.find_all("");

    // "*" and "**" should match everything
    assert!(m1.len() >= 2, "test should match * and **");
    assert!(m2.len() >= 3, "single char should match *, ?, and **");

    // Empty string should only match "*" and "**", not "?"
    assert!(m3.len() >= 2, "empty string should match * and **");
}

// =============================================================================
// V2 FORMAT TESTS - Pattern matching with associated data
// =============================================================================

#[test]
fn test_v2_simple_pattern_with_data() {
    let patterns = vec!["*.evil.com", "malware.*"];

    // Build threat data
    let mut threat1 = HashMap::new();
    threat1.insert(
        "threat_level".to_string(),
        DataValue::String("high".to_string()),
    );
    threat1.insert(
        "category".to_string(),
        DataValue::String("phishing".to_string()),
    );

    let mut threat2 = HashMap::new();
    threat2.insert(
        "threat_level".to_string(),
        DataValue::String("critical".to_string()),
    );
    threat2.insert(
        "category".to_string(),
        DataValue::String("malware".to_string()),
    );

    let data_values = vec![Some(DataValue::Map(threat1)), Some(DataValue::Map(threat2))];

    let pg = Paraglob::build_from_patterns_with_data(
        &patterns,
        Some(&data_values),
        MatchMode::CaseSensitive,
    )
    .unwrap();

    // Verify v2 format
    assert!(pg.has_data_section(), "Should be v2 format with data");

    // Verify we can retrieve data
    let data0 = pg.get_pattern_data(0).expect("Pattern 0 should have data");
    let data1 = pg.get_pattern_data(1).expect("Pattern 1 should have data");

    // Check data values
    if let DataValue::Map(m) = data0 {
        assert_eq!(
            m.get("threat_level"),
            Some(&DataValue::String("high".to_string()))
        );
        assert_eq!(
            m.get("category"),
            Some(&DataValue::String("phishing".to_string()))
        );
    } else {
        panic!("Expected Map data for pattern 0");
    }

    if let DataValue::Map(m) = data1 {
        assert_eq!(
            m.get("threat_level"),
            Some(&DataValue::String("critical".to_string()))
        );
    } else {
        panic!("Expected Map data for pattern 1");
    }
}

#[test]
fn test_v2_backward_compatibility_v1_format() {
    // Build old-style v1 format (no data)
    let patterns = vec!["*.txt", "test*"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    // Should NOT be v2 format
    assert!(
        !pg.has_data_section(),
        "V1 format should not have data section"
    );

    // Trying to get data should return None
    assert!(
        pg.get_pattern_data(0).is_none(),
        "V1 format should have no data"
    );
    assert!(
        pg.get_pattern_data(1).is_none(),
        "V1 format should have no data"
    );
}

#[test]
fn test_v2_data_deduplication() {
    let patterns = vec!["pattern1", "pattern2", "pattern3"];

    // All patterns get the SAME data
    let same_data = DataValue::String("shared_value".to_string());
    let data_values = vec![
        Some(same_data.clone()),
        Some(same_data.clone()),
        Some(same_data),
    ];

    let pg = Paraglob::build_from_patterns_with_data(
        &patterns,
        Some(&data_values),
        MatchMode::CaseSensitive,
    )
    .unwrap();

    // All patterns should have data
    assert!(pg.get_pattern_data(0).is_some());
    assert!(pg.get_pattern_data(1).is_some());
    assert!(pg.get_pattern_data(2).is_some());

    // Verify deduplication worked (all point to same data)
    let data0 = pg.get_pattern_data(0).unwrap();
    let data1 = pg.get_pattern_data(1).unwrap();
    let data2 = pg.get_pattern_data(2).unwrap();

    assert_eq!(data0, data1);
    assert_eq!(data1, data2);
}

#[test]
fn test_v2_roundtrip_serialization() {
    let patterns = vec!["*.evil.com", "malware.*", "test*"];

    let mut threat_data = HashMap::new();
    threat_data.insert("score".to_string(), DataValue::Uint32(95));
    threat_data.insert("active".to_string(), DataValue::Bool(true));

    let data_values = vec![
        Some(DataValue::Map(threat_data.clone())),
        Some(DataValue::Map(threat_data)),
        Some(DataValue::String("test_data".to_string())),
    ];

    let pg = Paraglob::build_from_patterns_with_data(
        &patterns,
        Some(&data_values),
        MatchMode::CaseSensitive,
    )
    .unwrap();

    // Serialize
    let bytes = to_bytes(&pg);

    // Deserialize
    let pg2 = from_bytes(&bytes, MatchMode::CaseSensitive).unwrap();

    // Verify format
    assert!(pg2.has_data_section(), "Deserialized should be v2 format");

    // Verify data preserved
    let data0 = pg2
        .get_pattern_data(0)
        .expect("Pattern 0 data should survive roundtrip");
    let data2 = pg2
        .get_pattern_data(2)
        .expect("Pattern 2 data should survive roundtrip");

    if let DataValue::Map(m) = data0 {
        assert_eq!(m.get("score"), Some(&DataValue::Uint32(95)));
        assert_eq!(m.get("active"), Some(&DataValue::Bool(true)));
    } else {
        panic!("Expected Map after roundtrip");
    }

    assert_eq!(data2, DataValue::String("test_data".to_string()));
}

#[test]
fn test_v2_partial_data_coverage() {
    // Not all patterns need data
    let patterns = vec!["pattern1", "pattern2", "pattern3"];

    let data_values = vec![
        Some(DataValue::String("has_data".to_string())),
        None, // No data for pattern2
        Some(DataValue::Uint32(42)),
    ];

    let pg = Paraglob::build_from_patterns_with_data(
        &patterns,
        Some(&data_values),
        MatchMode::CaseSensitive,
    )
    .unwrap();

    // Should still be v2 format (has some data)
    assert!(pg.has_data_section());

    // Check individual patterns
    assert!(
        pg.get_pattern_data(0).is_some(),
        "Pattern 0 should have data"
    );
    assert!(
        pg.get_pattern_data(1).is_none(),
        "Pattern 1 should NOT have data"
    );
    assert!(
        pg.get_pattern_data(2).is_some(),
        "Pattern 2 should have data"
    );
}

#[test]
fn test_v2_complex_nested_data() {
    let patterns = vec!["threat.*"];

    // Build complex nested structure
    let mut indicators = HashMap::new();
    indicators.insert("ip_count".to_string(), DataValue::Uint32(42));
    indicators.insert("domain_count".to_string(), DataValue::Uint32(15));

    let mut threat_data = HashMap::new();
    threat_data.insert("level".to_string(), DataValue::String("high".to_string()));
    threat_data.insert("confidence".to_string(), DataValue::Float(0.95));
    threat_data.insert("first_seen".to_string(), DataValue::Uint64(1704067200));
    threat_data.insert("indicators".to_string(), DataValue::Map(indicators));
    threat_data.insert(
        "tags".to_string(),
        DataValue::Array(vec![
            DataValue::String("botnet".to_string()),
            DataValue::String("c2".to_string()),
        ]),
    );
    threat_data.insert("active".to_string(), DataValue::Bool(true));

    let data_values = vec![Some(DataValue::Map(threat_data))];

    let pg = Paraglob::build_from_patterns_with_data(
        &patterns,
        Some(&data_values),
        MatchMode::CaseSensitive,
    )
    .unwrap();

    // Retrieve and verify complex structure
    let data = pg.get_pattern_data(0).expect("Should have data");

    if let DataValue::Map(m) = data {
        assert_eq!(m.get("level"), Some(&DataValue::String("high".to_string())));
        assert_eq!(m.get("active"), Some(&DataValue::Bool(true)));

        // Check nested map
        if let Some(DataValue::Map(ind)) = m.get("indicators") {
            assert_eq!(ind.get("ip_count"), Some(&DataValue::Uint32(42)));
        } else {
            panic!("Expected nested indicators map");
        }

        // Check array
        if let Some(DataValue::Array(tags)) = m.get("tags") {
            assert_eq!(tags.len(), 2);
            assert!(tags.contains(&DataValue::String("botnet".to_string())));
        } else {
            panic!("Expected tags array");
        }
    } else {
        panic!("Expected Map data");
    }
}

#[test]
fn test_v2_matching_with_data_retrieval() {
    let patterns = vec!["*.evil.com", "malware.*", "test*"];

    let mut data1 = HashMap::new();
    data1.insert(
        "id".to_string(),
        DataValue::String("THREAT-001".to_string()),
    );

    let mut data2 = HashMap::new();
    data2.insert(
        "id".to_string(),
        DataValue::String("THREAT-002".to_string()),
    );

    let mut data3 = HashMap::new();
    data3.insert("id".to_string(), DataValue::String("TEST-001".to_string()));

    let data_values = vec![
        Some(DataValue::Map(data1)),
        Some(DataValue::Map(data2)),
        Some(DataValue::Map(data3)),
    ];

    let pg = Paraglob::build_from_patterns_with_data(
        &patterns,
        Some(&data_values),
        MatchMode::CaseSensitive,
    )
    .unwrap();

    // Find matches
    let matches = pg.find_all("test.evil.com");
    assert!(!matches.is_empty(), "Should match some patterns");

    // Retrieve data for matched patterns
    for &pattern_id in &matches {
        let data = pg.get_pattern_data(pattern_id);
        assert!(
            data.is_some(),
            "Matched pattern {} should have data",
            pattern_id
        );

        // Verify it's a map with an ID
        if let Some(DataValue::Map(m)) = data {
            assert!(m.contains_key("id"), "Data should have id field");
        }
    }
}

#[test]
fn test_v2_all_mmdb_data_types() {
    let patterns = vec!["test"];

    // Build data with all MMDB types
    let mut data = HashMap::new();
    data.insert("string".to_string(), DataValue::String("hello".to_string()));
    data.insert("uint16".to_string(), DataValue::Uint16(12345));
    data.insert("uint32".to_string(), DataValue::Uint32(0xDEADBEEF));
    data.insert("uint64".to_string(), DataValue::Uint64(0x123456789ABCDEF0));
    data.insert(
        "uint128".to_string(),
        DataValue::Uint128(0x0123456789ABCDEF0123456789ABCDEF),
    );
    data.insert("int32".to_string(), DataValue::Int32(-42));
    data.insert(
        "double".to_string(),
        DataValue::Double(std::f64::consts::PI),
    );
    data.insert("float".to_string(), DataValue::Float(std::f32::consts::E));
    data.insert("bool_true".to_string(), DataValue::Bool(true));
    data.insert("bool_false".to_string(), DataValue::Bool(false));
    data.insert(
        "bytes".to_string(),
        DataValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    );
    data.insert(
        "array".to_string(),
        DataValue::Array(vec![
            DataValue::String("a".to_string()),
            DataValue::Uint32(1),
        ]),
    );

    let data_values = vec![Some(DataValue::Map(data))];

    let pg = Paraglob::build_from_patterns_with_data(
        &patterns,
        Some(&data_values),
        MatchMode::CaseSensitive,
    )
    .unwrap();

    // Serialize and deserialize to test all types survive roundtrip
    let bytes = to_bytes(&pg);
    let pg2 = from_bytes(&bytes, MatchMode::CaseSensitive).unwrap();

    let data = pg2.get_pattern_data(0).expect("Should have data");

    if let DataValue::Map(m) = data {
        assert_eq!(
            m.get("string"),
            Some(&DataValue::String("hello".to_string()))
        );
        assert_eq!(m.get("uint16"), Some(&DataValue::Uint16(12345)));
        assert_eq!(m.get("uint32"), Some(&DataValue::Uint32(0xDEADBEEF)));
        assert_eq!(m.get("int32"), Some(&DataValue::Int32(-42)));
        assert_eq!(m.get("bool_true"), Some(&DataValue::Bool(true)));
        assert_eq!(m.get("bool_false"), Some(&DataValue::Bool(false)));
        // Float comparison with tolerance
        if let Some(DataValue::Float(f)) = m.get("float") {
            assert!((f - std::f32::consts::E).abs() < 0.0001);
        }
    } else {
        panic!("Expected Map data");
    }
}

#[test]
fn test_v2_incremental_builder() {
    use matchy::bench_api::ParaglobBuilder;

    let mut builder = ParaglobBuilder::new(MatchMode::CaseSensitive);

    // Add patterns incrementally
    let id1 = builder.add_pattern("*.txt").unwrap();
    let id2 = builder.add_pattern("test_*").unwrap();

    // Add pattern with data
    let mut threat_data = HashMap::new();
    threat_data.insert("level".to_string(), DataValue::String("high".to_string()));
    threat_data.insert("score".to_string(), DataValue::Uint32(95));

    let id3 = builder
        .add_pattern_with_data("*.evil.com", Some(DataValue::Map(threat_data)))
        .unwrap();

    // Build state verified indirectly by successful adds above

    // Build final matcher
    let pg = builder.build().unwrap();

    // Test matching
    let matches = pg.find_all("test_file.txt");
    assert!(matches.contains(&id1));
    assert!(matches.contains(&id2));

    let matches2 = pg.find_all("phishing.evil.com");
    assert!(matches2.contains(&id3));

    // Verify data retrieval
    let data = pg
        .get_pattern_data(id3)
        .expect("Pattern 3 should have data");
    if let DataValue::Map(m) = data {
        assert_eq!(m.get("level"), Some(&DataValue::String("high".to_string())));
        assert_eq!(m.get("score"), Some(&DataValue::Uint32(95)));
    } else {
        panic!("Expected Map data");
    }
}

#[test]
fn test_v2_incremental_builder_duplicate_handling() {
    use matchy::bench_api::ParaglobBuilder;

    let mut builder = ParaglobBuilder::new(MatchMode::CaseSensitive);

    // Add same pattern twice
    let id1 = builder.add_pattern("*.txt").unwrap();
    let id2 = builder.add_pattern("*.txt").unwrap();

    // Should return the same ID (deduplication)
    assert_eq!(id1, id2);

    let pg = builder.build().unwrap();
    let matches = pg.find_all("file.txt");

    // Should only match once
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0], id1);
}
