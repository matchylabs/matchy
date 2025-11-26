// Test for IP longest prefix match bug
//
// Bug: When a /32 single IP is loaded BEFORE the /24 subnet it belongs to,
// the lookup for that IP fails to return the most specific match.

use matchy::database::{Database, QueryResult};
use matchy::mmdb_builder::DatabaseBuilder;
use matchy::DataValue;
use matchy::MatchMode;
use std::collections::HashMap;

#[test]
fn test_ip_specific_before_subnet() {
    // This test reproduces the bug: /32 loaded BEFORE /24
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    // Add single IP FIRST (192.0.2.1/32)
    let mut data1 = HashMap::new();
    data1.insert(
        "category".to_string(),
        DataValue::String("single ip address!!!".to_string()),
    );
    data1.insert(
        "threat_level".to_string(),
        DataValue::String("high".to_string()),
    );
    builder.add_ip("192.0.2.1", data1).unwrap();

    // Add broader subnet AFTER (192.0.2.0/24)
    let mut data2 = HashMap::new();
    data2.insert(
        "category".to_string(),
        DataValue::String(" medium subnet!!!".to_string()),
    );
    data2.insert(
        "threat_level".to_string(),
        DataValue::String("blah".to_string()),
    );
    builder.add_ip("192.0.2.0/24", data2).unwrap();

    // Build database
    let db_bytes = builder.build().unwrap();
    let db = Database::from_bytes(db_bytes).unwrap();

    // Query for the specific IP - should return the /32 match, not the /24
    let result = db.lookup_ip("192.0.2.1".parse().unwrap()).unwrap();
    assert!(
        matches!(result, Some(QueryResult::Ip { .. })),
        "Should find data for 192.0.2.1"
    );

    if let Some(QueryResult::Ip { data, prefix_len }) = result {
        // Should match the /32 entry (most specific)
        assert_eq!(
            prefix_len, 32,
            "Expected /32 prefix length, got /{}",
            prefix_len
        );

        let category = match &data {
            DataValue::Map(m) => m
                .get("category")
                .and_then(|v| {
                    if let DataValue::String(s) = v {
                        Some(s.as_str())
                    } else {
                        None
                    }
                })
                .unwrap(),
            _ => panic!("Expected map data"),
        };

        // Should match the /32 entry, not the /24
        assert_eq!(
            category, "single ip address!!!",
            "Expected longest prefix match (/32), but got: {}",
            category
        );
    }
}

#[test]
fn test_ip_specific_after_subnet() {
    // This test should work: /32 loaded AFTER /24
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    // Add broader subnet FIRST (192.0.2.0/24)
    let mut data2 = HashMap::new();
    data2.insert(
        "category".to_string(),
        DataValue::String(" medium subnet!!!".to_string()),
    );
    data2.insert(
        "threat_level".to_string(),
        DataValue::String("blah".to_string()),
    );
    builder.add_ip("192.0.2.0/24", data2).unwrap();

    // Add single IP AFTER (192.0.2.1/32)
    let mut data1 = HashMap::new();
    data1.insert(
        "category".to_string(),
        DataValue::String("single ip address!!!".to_string()),
    );
    data1.insert(
        "threat_level".to_string(),
        DataValue::String("high".to_string()),
    );
    builder.add_ip("192.0.2.1", data1).unwrap();

    // Build database
    let db_bytes = builder.build().unwrap();
    let db = Database::from_bytes(db_bytes).unwrap();

    // Query for the specific IP - should return the /32 match
    let result = db.lookup_ip("192.0.2.1".parse().unwrap()).unwrap();
    assert!(
        matches!(result, Some(QueryResult::Ip { .. })),
        "Should find data for 192.0.2.1"
    );

    if let Some(QueryResult::Ip { data, prefix_len }) = result {
        // Should match the /32 entry (most specific)
        assert_eq!(
            prefix_len, 32,
            "Expected /32 prefix length, got /{}",
            prefix_len
        );

        let category = match &data {
            DataValue::Map(m) => m
                .get("category")
                .and_then(|v| {
                    if let DataValue::String(s) = v {
                        Some(s.as_str())
                    } else {
                        None
                    }
                })
                .unwrap(),
            _ => panic!("Expected map data"),
        };

        // Should match the /32 entry
        assert_eq!(
            category, "single ip address!!!",
            "Expected longest prefix match (/32), but got: {}",
            category
        );
    }
}

#[test]
fn test_multiple_overlapping_prefixes() {
    // Test with multiple overlapping prefixes of different lengths
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    // Add in order: /8 -> /32 -> /24
    let mut data1 = HashMap::new();
    data1.insert("level".to_string(), DataValue::String("8".to_string()));
    builder.add_ip("192.0.0.0/8", data1).unwrap();

    let mut data2 = HashMap::new();
    data2.insert("level".to_string(), DataValue::String("32".to_string()));
    builder.add_ip("192.0.2.1", data2).unwrap();

    let mut data3 = HashMap::new();
    data3.insert("level".to_string(), DataValue::String("24".to_string()));
    builder.add_ip("192.0.2.0/24", data3).unwrap();

    // Build database
    let db_bytes = builder.build().unwrap();
    let db = Database::from_bytes(db_bytes).unwrap();

    // Helper to extract level string from QueryResult
    let get_level = |result: Option<QueryResult>| -> String {
        if let Some(QueryResult::Ip { data, .. }) = result {
            match &data {
                DataValue::Map(m) => m
                    .get("level")
                    .and_then(|v| {
                        if let DataValue::String(s) = v {
                            Some(s.clone())
                        } else {
                            None
                        }
                    })
                    .unwrap(),
                _ => panic!("Expected map data"),
            }
        } else {
            panic!("Expected IP result");
        }
    };

    // Query for 192.0.2.1 - should match /32 (most specific)
    let result = db.lookup_ip("192.0.2.1".parse().unwrap()).unwrap();
    let level = get_level(result);
    assert_eq!(level, "32", "Should match /32 prefix");

    // Query for 192.0.2.2 - should match /24 (next most specific)
    let result = db.lookup_ip("192.0.2.2".parse().unwrap()).unwrap();
    let level = get_level(result);
    assert_eq!(level, "24", "Should match /24 prefix");

    // Query for 192.1.1.1 - should match /8 (least specific)
    let result = db.lookup_ip("192.1.1.1".parse().unwrap()).unwrap();
    let level = get_level(result);
    assert_eq!(level, "8", "Should match /8 prefix");
}

#[test]
fn test_simple_two_level() {
    // Simpler test: just /24 and /32
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    // Add /32 first
    let mut data1 = HashMap::new();
    data1.insert("level".to_string(), DataValue::String("32".to_string()));
    builder.add_ip("10.0.0.1", data1).unwrap();

    // Add /24 second
    let mut data2 = HashMap::new();
    data2.insert("level".to_string(), DataValue::String("24".to_string()));
    builder.add_ip("10.0.0.0/24", data2).unwrap();

    // Build database
    let db_bytes = builder.build().unwrap();
    let db = Database::from_bytes(db_bytes).unwrap();

    // Helper to extract level string from QueryResult
    let get_level = |result: Option<QueryResult>| -> String {
        if let Some(QueryResult::Ip { data, .. }) = result {
            match &data {
                DataValue::Map(m) => m
                    .get("level")
                    .and_then(|v| {
                        if let DataValue::String(s) = v {
                            Some(s.clone())
                        } else {
                            None
                        }
                    })
                    .unwrap(),
                _ => panic!("Expected map data"),
            }
        } else {
            panic!("Expected IP result");
        }
    };

    // 10.0.0.1 should match /32
    let result = db.lookup_ip("10.0.0.1".parse().unwrap()).unwrap();
    let level = get_level(result);
    assert_eq!(level, "32", "10.0.0.1 should match /32 prefix");

    // 10.0.0.2 should match /24
    let result = db.lookup_ip("10.0.0.2".parse().unwrap()).unwrap();
    let level = get_level(result);
    assert_eq!(level, "24", "10.0.0.2 should match /24 prefix");
}

#[test]
fn test_ipv6_longest_prefix_match() {
    // Test that IPv6 also handles longest prefix matching correctly
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    // Add /64 first, then /128, then /96 (out of order)
    let mut data1 = HashMap::new();
    data1.insert("level".to_string(), DataValue::String("64".to_string()));
    builder.add_ip("2001:db8::/64", data1).unwrap();

    let mut data2 = HashMap::new();
    data2.insert("level".to_string(), DataValue::String("128".to_string()));
    builder.add_ip("2001:db8::1", data2).unwrap();

    let mut data3 = HashMap::new();
    data3.insert("level".to_string(), DataValue::String("96".to_string()));
    builder.add_ip("2001:db8::/96", data3).unwrap();

    // Build database
    let db_bytes = builder.build().unwrap();
    let db = Database::from_bytes(db_bytes).unwrap();

    // Helper to extract level string from QueryResult
    let get_level = |result: Option<QueryResult>| -> String {
        if let Some(QueryResult::Ip { data, .. }) = result {
            match &data {
                DataValue::Map(m) => m
                    .get("level")
                    .and_then(|v| {
                        if let DataValue::String(s) = v {
                            Some(s.clone())
                        } else {
                            None
                        }
                    })
                    .unwrap(),
                _ => panic!("Expected map data"),
            }
        } else {
            panic!("Expected IP result");
        }
    };

    // 2001:db8::1 should match /128 (most specific)
    let result = db.lookup_ip("2001:db8::1".parse().unwrap()).unwrap();
    let level = get_level(result);
    assert_eq!(level, "128", "2001:db8::1 should match /128 prefix");

    // 2001:db8::2 should match /96 (next most specific)
    let result = db.lookup_ip("2001:db8::2".parse().unwrap()).unwrap();
    let level = get_level(result);
    assert_eq!(level, "96", "2001:db8::2 should match /96 prefix");

    // 2001:db8::1:0:0 should match /64 (least specific, outside /96)
    let result = db.lookup_ip("2001:db8::1:0:0".parse().unwrap()).unwrap();
    let level = get_level(result);
    assert_eq!(level, "64", "2001:db8::1:0:0 should match /64 prefix");
}
