// Test for sequential builder bug
//
// Bug: When creating multiple builders sequentially (create → add → save → free → repeat),
// data from previous builders incorrectly appears in subsequent builders.

use matchy::database::QueryResult;
use matchy::{Database, DatabaseBuilder};
use matchy_match_mode::MatchMode;
use std::collections::HashMap;
use tempfile::tempdir;

/// Helper to check if a lookup result is an actual match (not NotFound)
fn is_match(result: &Option<QueryResult>) -> bool {
    match result {
        Some(QueryResult::NotFound) => false,
        Some(_) => true,
        None => false,
    }
}

/// Test that multiple sequential builders don't share state
#[test]
fn test_sequential_builders_isolated() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let db1_path = temp_dir.path().join("db1.mxy");
    let db2_path = temp_dir.path().join("db2.mxy");
    let db3_path = temp_dir.path().join("db3.mxy");

    // Builder 1: Add IP 1.1.1.1 with data {"name": "first"}
    {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut data = HashMap::new();
        data.insert(
            "name".to_string(),
            matchy_data_format::DataValue::String("first".to_string()),
        );
        builder.add_entry("1.1.1.1", data).unwrap();
        let bytes = builder.build().unwrap();
        std::fs::write(&db1_path, bytes).unwrap();
    }

    // Builder 2: Add IP 2.2.2.2 with data {"name": "second"}
    {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut data = HashMap::new();
        data.insert(
            "name".to_string(),
            matchy_data_format::DataValue::String("second".to_string()),
        );
        builder.add_entry("2.2.2.2", data).unwrap();
        let bytes = builder.build().unwrap();
        std::fs::write(&db2_path, bytes).unwrap();
    }

    // Builder 3: Empty database (no entries)
    {
        let builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let bytes = builder.build().unwrap();
        std::fs::write(&db3_path, bytes).unwrap();
    }

    // Now verify the databases contain the correct data

    // DB1 should have 1.1.1.1 -> "first"
    let db1 = Database::from(db1_path.to_str().unwrap())
        .open()
        .expect("Failed to open db1");
    let result1 = db1.lookup("1.1.1.1").expect("lookup failed");
    assert!(is_match(&result1), "DB1 should find 1.1.1.1");

    // DB1 should NOT have 2.2.2.2
    let result1_other = db1.lookup("2.2.2.2").expect("lookup failed");
    assert!(!is_match(&result1_other), "DB1 should NOT find 2.2.2.2");

    // DB2 should have 2.2.2.2 -> "second"
    let db2 = Database::from(db2_path.to_str().unwrap())
        .open()
        .expect("Failed to open db2");
    let result2 = db2.lookup("2.2.2.2").expect("lookup failed");
    assert!(is_match(&result2), "DB2 should find 2.2.2.2");

    // DB2 should NOT have 1.1.1.1
    let result2_other = db2.lookup("1.1.1.1").expect("lookup failed");
    assert!(!is_match(&result2_other), "DB2 should NOT find 1.1.1.1");

    // DB3 should be empty - should NOT find 1.1.1.1 (the bug would show this)
    let db3 = Database::from(db3_path.to_str().unwrap())
        .open()
        .expect("Failed to open db3");
    let result3 = db3.lookup("1.1.1.1").expect("lookup failed");
    assert!(
        !is_match(&result3),
        "DB3 (empty) should NOT find 1.1.1.1 - BUG: data leaked from builder 1!"
    );
    let result3_other = db3.lookup("2.2.2.2").expect("lookup failed");
    assert!(
        !is_match(&result3_other),
        "DB3 (empty) should NOT find 2.2.2.2"
    );
}

/// Test the C API pattern more closely - simulating save-then-reuse pattern
/// The bug description suggests data gets "shifted" by one builder
#[test]
fn test_sequential_builders_c_api_pattern() {
    let temp_dir = tempdir().expect("Failed to create temp dir");

    // This test simulates what happens in the C API:
    // 1. Create builder
    // 2. Add entries
    // 3. Save (which replaces internal builder with empty one)
    // 4. Free builder
    // 5. Create new builder
    // 6. Add different entries
    // 7. Save
    // etc.

    let db1_path = temp_dir.path().join("capi_db1.mxy");
    let db2_path = temp_dir.path().join("capi_db2.mxy");
    let db3_path = temp_dir.path().join("capi_db3.mxy");

    // Simulate C API matchy_builder_save behavior:
    // It does std::mem::replace to take ownership, leaving an empty builder behind

    // Builder 1
    let mut builder1 = DatabaseBuilder::new(MatchMode::CaseSensitive);
    let mut data1 = HashMap::new();
    data1.insert(
        "name".to_string(),
        matchy_data_format::DataValue::String("first".to_string()),
    );
    builder1.add_entry("1.1.1.1", data1).unwrap();

    // Simulate matchy_builder_save: take ownership via replace
    let builder_to_build = std::mem::replace(
        &mut builder1,
        DatabaseBuilder::new(MatchMode::CaseSensitive),
    );
    let bytes1 = builder_to_build.build().unwrap();
    std::fs::write(&db1_path, &bytes1).unwrap();
    // builder1 is now empty (the replacement)
    drop(builder1); // Simulate matchy_builder_free

    // Builder 2
    let mut builder2 = DatabaseBuilder::new(MatchMode::CaseSensitive);
    let mut data2 = HashMap::new();
    data2.insert(
        "name".to_string(),
        matchy_data_format::DataValue::String("second".to_string()),
    );
    builder2.add_entry("2.2.2.2", data2).unwrap();

    let builder_to_build = std::mem::replace(
        &mut builder2,
        DatabaseBuilder::new(MatchMode::CaseSensitive),
    );
    let bytes2 = builder_to_build.build().unwrap();
    std::fs::write(&db2_path, &bytes2).unwrap();
    drop(builder2);

    // Builder 3 - empty
    let mut builder3 = DatabaseBuilder::new(MatchMode::CaseSensitive);
    let builder_to_build = std::mem::replace(
        &mut builder3,
        DatabaseBuilder::new(MatchMode::CaseSensitive),
    );
    let bytes3 = builder_to_build.build().unwrap();
    std::fs::write(&db3_path, &bytes3).unwrap();
    drop(builder3);

    // Verify
    let db1 = Database::from(db1_path.to_str().unwrap()).open().unwrap();
    let db2 = Database::from(db2_path.to_str().unwrap()).open().unwrap();
    let db3 = Database::from(db3_path.to_str().unwrap()).open().unwrap();

    // DB1: 1.1.1.1 should be found
    assert!(
        is_match(&db1.lookup("1.1.1.1").unwrap()),
        "DB1 should have 1.1.1.1"
    );
    assert!(
        !is_match(&db1.lookup("2.2.2.2").unwrap()),
        "DB1 should NOT have 2.2.2.2"
    );

    // DB2: 2.2.2.2 should be found (BUG: might be empty if data shifted)
    assert!(
        is_match(&db2.lookup("2.2.2.2").unwrap()),
        "DB2 should have 2.2.2.2 - BUG if missing!"
    );
    assert!(
        !is_match(&db2.lookup("1.1.1.1").unwrap()),
        "DB2 should NOT have 1.1.1.1"
    );

    // DB3: should be empty (BUG: might have 1.1.1.1 if data shifted)
    assert!(
        !is_match(&db3.lookup("1.1.1.1").unwrap()),
        "DB3 should NOT have 1.1.1.1 - BUG: builder 1's data leaked!"
    );
    assert!(
        !is_match(&db3.lookup("2.2.2.2").unwrap()),
        "DB3 should NOT have 2.2.2.2"
    );
}

/// Test interleaved queries on multiple databases
/// This tests the scenario that would cause cache thrashing with the old design
#[test]
fn test_interleaved_queries_multiple_databases() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let db1_path = temp_dir.path().join("interleave_db1.mxy");
    let db2_path = temp_dir.path().join("interleave_db2.mxy");

    // Build DB1: contains 1.1.1.1
    {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut data = HashMap::new();
        data.insert(
            "source".to_string(),
            matchy_data_format::DataValue::String("db1".to_string()),
        );
        builder.add_entry("1.1.1.1", data).unwrap();
        let bytes = builder.build().unwrap();
        std::fs::write(&db1_path, bytes).unwrap();
    }

    // Build DB2: contains 1.1.1.1 with DIFFERENT data
    {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut data = HashMap::new();
        data.insert(
            "source".to_string(),
            matchy_data_format::DataValue::String("db2".to_string()),
        );
        builder.add_entry("1.1.1.1", data).unwrap();
        let bytes = builder.build().unwrap();
        std::fs::write(&db2_path, bytes).unwrap();
    }

    // Open both databases
    let db1 = Database::from(db1_path.to_str().unwrap()).open().unwrap();
    let db2 = Database::from(db2_path.to_str().unwrap()).open().unwrap();

    // Interleave queries - same query string, different databases
    // Each should return its own data, not cached data from the other
    for _ in 0..10 {
        let r1 = db1.lookup("1.1.1.1").unwrap();
        let r2 = db2.lookup("1.1.1.1").unwrap();

        // Extract the "source" field from each result
        let source1 = match &r1 {
            Some(QueryResult::Ip { data, .. }) => match data {
                matchy_data_format::DataValue::Map(m) => match m.get("source") {
                    Some(matchy_data_format::DataValue::String(s)) => s.as_str(),
                    _ => panic!("Expected source string in db1 result"),
                },
                _ => panic!("Expected map in db1 result"),
            },
            _ => panic!("Expected Ip result from db1"),
        };

        let source2 = match &r2 {
            Some(QueryResult::Ip { data, .. }) => match data {
                matchy_data_format::DataValue::Map(m) => match m.get("source") {
                    Some(matchy_data_format::DataValue::String(s)) => s.as_str(),
                    _ => panic!("Expected source string in db2 result"),
                },
                _ => panic!("Expected map in db2 result"),
            },
            _ => panic!("Expected Ip result from db2"),
        };

        assert_eq!(
            source1, "db1",
            "DB1 query returned wrong data (cache collision!)"
        );
        assert_eq!(
            source2, "db2",
            "DB2 query returned wrong data (cache collision!)"
        );
    }
}

/// Test with patterns (globs) to ensure the bug affects all entry types
#[test]
fn test_sequential_builders_with_patterns() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let db1_path = temp_dir.path().join("pattern_db1.mxy");
    let db2_path = temp_dir.path().join("pattern_db2.mxy");

    // Builder 1: pattern "*.evil.com"
    {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut data = HashMap::new();
        data.insert(
            "category".to_string(),
            matchy_data_format::DataValue::String("malware".to_string()),
        );
        builder.add_entry("*.evil.com", data).unwrap();
        let bytes = builder.build().unwrap();
        std::fs::write(&db1_path, bytes).unwrap();
    }

    // Builder 2: pattern "*.good.com"
    {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut data = HashMap::new();
        data.insert(
            "category".to_string(),
            matchy_data_format::DataValue::String("safe".to_string()),
        );
        builder.add_entry("*.good.com", data).unwrap();
        let bytes = builder.build().unwrap();
        std::fs::write(&db2_path, bytes).unwrap();
    }

    // Verify
    let db1 = Database::from(db1_path.to_str().unwrap()).open().unwrap();
    let db2 = Database::from(db2_path.to_str().unwrap()).open().unwrap();

    // DB1 should match *.evil.com
    assert!(
        is_match(&db1.lookup("test.evil.com").unwrap()),
        "DB1 should match *.evil.com"
    );
    assert!(
        !is_match(&db1.lookup("test.good.com").unwrap()),
        "DB1 should NOT match *.good.com"
    );

    // DB2 should match *.good.com
    assert!(
        is_match(&db2.lookup("test.good.com").unwrap()),
        "DB2 should match *.good.com"
    );
    assert!(
        !is_match(&db2.lookup("test.evil.com").unwrap()),
        "DB2 should NOT match *.evil.com - BUG if matched!"
    );
}
