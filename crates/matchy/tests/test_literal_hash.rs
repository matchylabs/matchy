use matchy::{DataValue, Database, DatabaseBuilder, MatchMode, QueryResult};
use std::collections::HashMap;
use tempfile::NamedTempFile;

#[test]
fn test_literal_exact_match() {
    // Build database with literals
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    let mut data = HashMap::new();
    data.insert("type".to_string(), DataValue::String("malware".to_string()));
    data.insert(
        "severity".to_string(),
        DataValue::String("high".to_string()),
    );

    builder.add_literal("evil.com", data.clone()).unwrap();
    builder.add_literal("bad.org", data.clone()).unwrap();
    builder.add_literal("threat.net", data).unwrap();

    // Build and save
    let db_bytes = builder.build().unwrap();
    let mut tmpfile = NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmpfile, &db_bytes).unwrap();

    // Load and test
    let db = Database::from(tmpfile.path().to_str().unwrap())
        .open()
        .unwrap();

    // Test exact match
    let result = db.lookup("evil.com").unwrap().unwrap();
    match result {
        QueryResult::Pattern { pattern_ids, data } => {
            assert_eq!(pattern_ids.len(), 1);
            assert!(data[0].is_some());
            if let Some(DataValue::Map(map)) = &data[0] {
                assert_eq!(
                    map.get("type"),
                    Some(&DataValue::String("malware".to_string()))
                );
            }
        }
        _ => panic!("Expected Pattern result"),
    }

    // Test no match
    let result = db.lookup("notfound.com").unwrap().unwrap();
    assert!(matches!(result, QueryResult::NotFound));
}

#[test]
fn test_literal_and_glob_both_match() {
    // Build database with BOTH a literal and a glob that match the same query
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    let mut literal_data = HashMap::new();
    literal_data.insert(
        "source".to_string(),
        DataValue::String("literal".to_string()),
    );
    literal_data.insert(
        "severity".to_string(),
        DataValue::String("high".to_string()),
    );

    let mut glob_data = HashMap::new();
    glob_data.insert("source".to_string(), DataValue::String("glob".to_string()));
    glob_data.insert(
        "severity".to_string(),
        DataValue::String("medium".to_string()),
    );

    // Add literal
    builder.add_literal("evil.com", literal_data).unwrap();

    // Add glob that also matches
    builder.add_glob("*.com", glob_data).unwrap();

    // Build and save
    let db_bytes = builder.build().unwrap();
    let mut tmpfile = NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmpfile, &db_bytes).unwrap();

    // Load and test
    let db = Database::from(tmpfile.path().to_str().unwrap())
        .open()
        .unwrap();

    // Query should match BOTH the literal AND the glob
    let result = db.lookup("evil.com").unwrap().unwrap();
    match result {
        QueryResult::Pattern { pattern_ids, data } => {
            // Should have 2 matches: one from literal, one from glob
            assert_eq!(pattern_ids.len(), 2, "Should match both literal and glob");

            // Verify we got data from both sources
            let sources: Vec<String> = data
                .iter()
                .filter_map(|d| {
                    if let Some(DataValue::Map(map)) = d {
                        if let Some(DataValue::String(s)) = map.get("source") {
                            return Some(s.clone());
                        }
                    }
                    None
                })
                .collect();

            assert!(sources.contains(&"literal".to_string()));
            assert!(sources.contains(&"glob".to_string()));
        }
        _ => panic!("Expected Pattern result"),
    }
}

#[test]
fn test_glob_only_match() {
    // Build database with only globs
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    let mut data = HashMap::new();
    data.insert(
        "type".to_string(),
        DataValue::String("phishing".to_string()),
    );

    builder.add_glob("*.phishing.com", data.clone()).unwrap();
    builder.add_glob("bad-*", data).unwrap();

    // Build and save
    let db_bytes = builder.build().unwrap();
    let mut tmpfile = NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmpfile, &db_bytes).unwrap();

    // Load and test
    let db = Database::from(tmpfile.path().to_str().unwrap())
        .open()
        .unwrap();

    // Test glob match
    let result = db.lookup("test.phishing.com").unwrap().unwrap();
    match result {
        QueryResult::Pattern { pattern_ids, .. } => {
            assert_eq!(pattern_ids.len(), 1);
        }
        _ => panic!("Expected Pattern result"),
    }

    // Test another glob match
    let result = db.lookup("bad-actor").unwrap().unwrap();
    match result {
        QueryResult::Pattern { pattern_ids, .. } => {
            assert_eq!(pattern_ids.len(), 1);
        }
        _ => panic!("Expected Pattern result"),
    }
}

#[test]
fn test_mixed_ip_literal_glob() {
    // Build database with IPs, literals, and globs
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    let mut ip_data = HashMap::new();
    ip_data.insert(
        "type".to_string(),
        DataValue::String("ip_threat".to_string()),
    );

    let mut literal_data = HashMap::new();
    literal_data.insert(
        "type".to_string(),
        DataValue::String("domain_threat".to_string()),
    );

    let mut glob_data = HashMap::new();
    glob_data.insert(
        "type".to_string(),
        DataValue::String("pattern_threat".to_string()),
    );

    builder.add_ip("1.2.3.4", ip_data).unwrap();
    builder.add_literal("evil.com", literal_data).unwrap();
    builder.add_glob("*.bad.com", glob_data).unwrap();

    // Build and save
    let db_bytes = builder.build().unwrap();
    let mut tmpfile = NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmpfile, &db_bytes).unwrap();

    // Load and test
    let db = Database::from(tmpfile.path().to_str().unwrap())
        .open()
        .unwrap();

    // Test IP lookup
    let result = db.lookup("1.2.3.4").unwrap().unwrap();
    assert!(matches!(result, QueryResult::Ip { .. }));

    // Test literal lookup
    let result = db.lookup("evil.com").unwrap().unwrap();
    match result {
        QueryResult::Pattern { pattern_ids, .. } => {
            assert_eq!(pattern_ids.len(), 1);
        }
        _ => panic!("Expected Pattern result"),
    }

    // Test glob lookup
    let result = db.lookup("test.bad.com").unwrap().unwrap();
    match result {
        QueryResult::Pattern { pattern_ids, .. } => {
            assert_eq!(pattern_ids.len(), 1);
        }
        _ => panic!("Expected Pattern result"),
    }
}

#[test]
fn test_literal_with_special_chars() {
    // Test that literals with glob-like characters work correctly
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    let mut data = HashMap::new();
    data.insert(
        "note".to_string(),
        DataValue::String("has brackets".to_string()),
    );

    // These contain glob characters but should be treated as literals
    builder.add_literal("file[1].txt", data.clone()).unwrap();
    builder.add_literal("what?.com", data.clone()).unwrap();
    builder.add_literal("price*list", data).unwrap();

    // Build and save
    let db_bytes = builder.build().unwrap();
    let mut tmpfile = NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmpfile, &db_bytes).unwrap();

    // Load and test
    let db = Database::from(tmpfile.path().to_str().unwrap())
        .open()
        .unwrap();

    // These should match exactly
    assert!(matches!(
        db.lookup("file[1].txt").unwrap().unwrap(),
        QueryResult::Pattern { .. }
    ));
    assert!(matches!(
        db.lookup("what?.com").unwrap().unwrap(),
        QueryResult::Pattern { .. }
    ));
    assert!(matches!(
        db.lookup("price*list").unwrap().unwrap(),
        QueryResult::Pattern { .. }
    ));

    // These should NOT match (they're not the exact string)
    assert!(matches!(
        db.lookup("file2.txt").unwrap().unwrap(),
        QueryResult::NotFound
    ));
}

#[test]
fn test_builder_stats() {
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    let data = HashMap::new();
    builder.add_ip("1.2.3.4", data.clone()).unwrap();
    builder.add_literal("evil.com", data.clone()).unwrap();
    builder.add_literal("bad.org", data.clone()).unwrap();
    builder.add_glob("*.phishing.com", data).unwrap();

    let stats = builder.stats();
    assert_eq!(stats.total_entries, 4);
    assert_eq!(stats.ip_entries, 1);
    assert_eq!(stats.literal_entries, 2);
    assert_eq!(stats.glob_entries, 1);
}
