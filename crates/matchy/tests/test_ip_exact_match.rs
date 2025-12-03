//! Test exact IP matching behavior
//!
//! This test ensures that when individual IP addresses (as /32s) are inserted,
//! only those exact IPs are matched, not broader CIDR ranges.

use matchy::database::Database;
use matchy::DataValue;
use matchy::DatabaseBuilder;
use matchy::MatchMode;
use std::collections::HashMap;

#[test]
fn test_exact_ip_matching_no_overmatch() {
    // Insert specific IPs: 0.0.0.1, 0.0.0.3, 0.0.0.5
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
    let empty_data = HashMap::new();

    builder.add_ip("0.0.0.1", empty_data.clone()).unwrap();
    builder.add_ip("0.0.0.3", empty_data.clone()).unwrap();
    builder.add_ip("0.0.0.5", empty_data.clone()).unwrap();

    let db_bytes = builder.build().unwrap();
    let db = Database::from_bytes(db_bytes).unwrap();

    // These SHOULD match (inserted)
    let ip1 = "0.0.0.1".parse().unwrap();
    let ip3 = "0.0.0.3".parse().unwrap();
    let ip5 = "0.0.0.5".parse().unwrap();

    assert!(
        matches!(
            db.lookup_ip(ip1).unwrap(),
            Some(matchy::database::QueryResult::Ip { .. })
        ),
        "0.0.0.1 should be found"
    );
    assert!(
        matches!(
            db.lookup_ip(ip3).unwrap(),
            Some(matchy::database::QueryResult::Ip { .. })
        ),
        "0.0.0.3 should be found"
    );
    assert!(
        matches!(
            db.lookup_ip(ip5).unwrap(),
            Some(matchy::database::QueryResult::Ip { .. })
        ),
        "0.0.0.5 should be found"
    );

    // These should NOT match (not inserted)
    let ip0 = "0.0.0.0".parse().unwrap();
    let ip2 = "0.0.0.2".parse().unwrap();
    let ip4 = "0.0.0.4".parse().unwrap();
    let ip6 = "0.0.0.6".parse().unwrap();

    assert!(
        matches!(
            db.lookup_ip(ip0).unwrap(),
            Some(matchy::database::QueryResult::NotFound) | None
        ),
        "0.0.0.0 should NOT be found (not inserted)"
    );
    assert!(
        matches!(
            db.lookup_ip(ip2).unwrap(),
            Some(matchy::database::QueryResult::NotFound) | None
        ),
        "0.0.0.2 should NOT be found (not inserted)"
    );
    assert!(
        matches!(
            db.lookup_ip(ip4).unwrap(),
            Some(matchy::database::QueryResult::NotFound) | None
        ),
        "0.0.0.4 should NOT be found (not inserted)"
    );
    assert!(
        matches!(
            db.lookup_ip(ip6).unwrap(),
            Some(matchy::database::QueryResult::NotFound) | None
        ),
        "0.0.0.6 should NOT be found (not inserted)"
    );
}

#[test]
fn test_sequential_ips_no_range_expansion() {
    // Insert 10 sequential IPs
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
    let empty_data = HashMap::new();

    for i in 0..10 {
        builder
            .add_ip(&format!("10.0.0.{}", i), empty_data.clone())
            .unwrap();
    }

    let db_bytes = builder.build().unwrap();
    let db = Database::from_bytes(db_bytes).unwrap();

    // Inserted IPs should match
    for i in 0..10 {
        let ip = format!("10.0.0.{}", i).parse().unwrap();
        assert!(
            matches!(
                db.lookup_ip(ip).unwrap(),
                Some(matchy::database::QueryResult::Ip { .. })
            ),
            "10.0.0.{} should be found",
            i
        );
    }

    // IPs beyond our range should NOT match
    for i in 10..20 {
        let ip = format!("10.0.0.{}", i).parse().unwrap();
        assert!(
            matches!(
                db.lookup_ip(ip).unwrap(),
                Some(matchy::database::QueryResult::NotFound) | None
            ),
            "10.0.0.{} should NOT be found (not inserted)",
            i
        );
    }

    // Completely different subnet should not match
    let other = "10.0.1.0".parse().unwrap();
    assert!(
        matches!(
            db.lookup_ip(other).unwrap(),
            Some(matchy::database::QueryResult::NotFound) | None
        ),
        "10.0.1.0 should NOT be found"
    );
}

#[test]
fn test_sparse_ips_no_implicit_ranges() {
    // Insert IPs with gaps: 192.168.1.1, 192.168.1.100, 192.168.1.200
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
    let empty_data = HashMap::new();

    builder.add_ip("192.168.1.1", empty_data.clone()).unwrap();
    builder.add_ip("192.168.1.100", empty_data.clone()).unwrap();
    builder.add_ip("192.168.1.200", empty_data.clone()).unwrap();

    let db_bytes = builder.build().unwrap();
    let db = Database::from_bytes(db_bytes).unwrap();

    // Inserted IPs should match
    assert!(matches!(
        db.lookup_ip("192.168.1.1".parse().unwrap()).unwrap(),
        Some(matchy::database::QueryResult::Ip { .. })
    ));
    assert!(matches!(
        db.lookup_ip("192.168.1.100".parse().unwrap()).unwrap(),
        Some(matchy::database::QueryResult::Ip { .. })
    ));
    assert!(matches!(
        db.lookup_ip("192.168.1.200".parse().unwrap()).unwrap(),
        Some(matchy::database::QueryResult::Ip { .. })
    ));

    // IPs in between should NOT match
    assert!(
        matches!(
            db.lookup_ip("192.168.1.2".parse().unwrap()).unwrap(),
            Some(matchy::database::QueryResult::NotFound) | None
        ),
        "192.168.1.2 should NOT match (gap between 1 and 100)"
    );
    assert!(
        matches!(
            db.lookup_ip("192.168.1.50".parse().unwrap()).unwrap(),
            Some(matchy::database::QueryResult::NotFound) | None
        ),
        "192.168.1.50 should NOT match (gap between 1 and 100)"
    );
    assert!(
        matches!(
            db.lookup_ip("192.168.1.150".parse().unwrap()).unwrap(),
            Some(matchy::database::QueryResult::NotFound) | None
        ),
        "192.168.1.150 should NOT match (gap between 100 and 200)"
    );
    assert!(
        matches!(
            db.lookup_ip("192.168.1.250".parse().unwrap()).unwrap(),
            Some(matchy::database::QueryResult::NotFound) | None
        ),
        "192.168.1.250 should NOT match (after 200)"
    );
}

#[test]
fn test_cidr_vs_individual_ips() {
    // Insert a CIDR block and individual IPs to ensure they work differently
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
    let mut cidr_data = HashMap::new();
    cidr_data.insert("type".to_string(), DataValue::String("cidr".to_string()));

    let mut individual_data = HashMap::new();
    individual_data.insert(
        "type".to_string(),
        DataValue::String("individual".to_string()),
    );

    // Insert a /30 CIDR (covers 4 IPs: .0, .1, .2, .3)
    builder.add_ip("10.0.0.0/30", cidr_data.clone()).unwrap();

    // Insert individual IPs outside that range
    builder.add_ip("10.0.0.5", individual_data.clone()).unwrap();
    builder
        .add_ip("10.0.0.10", individual_data.clone())
        .unwrap();

    let db_bytes = builder.build().unwrap();
    let db = Database::from_bytes(db_bytes).unwrap();

    // CIDR range should match
    for i in 0..4 {
        let ip = format!("10.0.0.{}", i).parse().unwrap();
        let result = db.lookup_ip(ip).unwrap();
        assert!(
            matches!(result, Some(matchy::database::QueryResult::Ip { .. })),
            "10.0.0.{} should match CIDR",
            i
        );
    }

    // Gap between CIDR and individual IPs should NOT match
    let ip4 = "10.0.0.4".parse().unwrap();
    assert!(
        matches!(
            db.lookup_ip(ip4).unwrap(),
            Some(matchy::database::QueryResult::NotFound) | None
        ),
        "10.0.0.4 should NOT match (gap)"
    );

    // Individual IPs should match
    let ip5 = "10.0.0.5".parse().unwrap();
    let ip10 = "10.0.0.10".parse().unwrap();
    assert!(
        matches!(
            db.lookup_ip(ip5).unwrap(),
            Some(matchy::database::QueryResult::Ip { .. })
        ),
        "10.0.0.5 should match"
    );
    assert!(
        matches!(
            db.lookup_ip(ip10).unwrap(),
            Some(matchy::database::QueryResult::Ip { .. })
        ),
        "10.0.0.10 should match"
    );

    // IP between individuals should NOT match
    let ip7 = "10.0.0.7".parse().unwrap();
    assert!(
        matches!(
            db.lookup_ip(ip7).unwrap(),
            Some(matchy::database::QueryResult::NotFound) | None
        ),
        "10.0.0.7 should NOT match (gap between 5 and 10)"
    );
}
