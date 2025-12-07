// Test for stale NotFound cache bug
//
// Bug: When opening a database that doesn't contain an IP, querying it (caches NotFound),
// then dropping that database and opening a NEW database that DOES contain the IP,
// the cached NotFound from the first database is incorrectly returned.
//
// This was observed in Wireshark integration where:
// - DB_A has no entry for 80.239.174.89
// - DB_B has 80.239.0.0/16
// - Open DB_A, query 80.239.174.89 -> NotFound (cached)
// - Drop DB_A, Open DB_B
// - Query 80.239.174.89 -> STILL returns NotFound (BUG! Should return match)

use matchy::database::QueryResult;
use matchy::{Database, DatabaseBuilder, DatabaseOptions};
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

/// Test that cached NotFound doesn't persist across database instances
///
/// This reproduces the exact bug from Wireshark integration:
/// 1. Open DB without IP -> query returns NotFound (cached)
/// 2. Drop DB, open new DB WITH the IP
/// 3. Query same IP -> should return match, NOT stale NotFound
#[test]
fn test_stale_notfound_does_not_persist() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let db_a_path = temp_dir.path().join("db_a_no_match.mxy");
    let db_b_path = temp_dir.path().join("db_b_has_match.mxy");

    let test_ip = "80.239.174.89";

    // Create DB_A: Does NOT contain the test IP
    {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        // Add a different IP so it's not empty
        let mut data = HashMap::new();
        data.insert(
            "name".to_string(),
            matchy_data_format::DataValue::String("other".to_string()),
        );
        builder.add_entry("1.1.1.0/24", data).unwrap();
        let bytes = builder.build().unwrap();
        std::fs::write(&db_a_path, bytes).unwrap();
    }

    // Create DB_B: DOES contain the test IP (via 80.239.0.0/16)
    {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut data = HashMap::new();
        data.insert(
            "name".to_string(),
            matchy_data_format::DataValue::String("matched".to_string()),
        );
        builder.add_entry("80.239.0.0/16", data).unwrap();
        let bytes = builder.build().unwrap();
        std::fs::write(&db_b_path, bytes).unwrap();
    }

    // Step 1: Open DB_A and query the IP - should NOT match
    {
        let db_a = Database::open_with_options(DatabaseOptions {
            path: db_a_path.clone(),
            cache_capacity: Some(100), // Cache enabled!
            ..Default::default()
        })
        .expect("Failed to open DB_A");

        let result_a = db_a.lookup(test_ip).expect("Lookup failed");

        // Verify DB_A doesn't have the IP
        assert!(
            !is_match(&result_a),
            "DB_A should NOT match {}, but got: {:?}",
            test_ip,
            result_a
        );

        println!(
            "DB_A lookup for {}: {:?} (expected NotFound)",
            test_ip, result_a
        );

        // DB_A goes out of scope and is dropped here
    }

    // Step 2: Open DB_B and query the SAME IP - should MATCH
    {
        let db_b = Database::open_with_options(DatabaseOptions {
            path: db_b_path.clone(),
            cache_capacity: Some(100), // Cache enabled!
            ..Default::default()
        })
        .expect("Failed to open DB_B");

        let result_b = db_b.lookup(test_ip).expect("Lookup failed");

        // THIS IS THE BUG: If the cached NotFound from DB_A persists,
        // this assertion will FAIL
        assert!(
            is_match(&result_b),
            "BUG: DB_B SHOULD match {} but got {:?} - stale NotFound from DB_A persisted!",
            test_ip,
            result_b
        );

        println!(
            "DB_B lookup for {}: {:?} (expected match)",
            test_ip, result_b
        );

        // Verify we got the right data
        if let Some(QueryResult::Ip { data, prefix_len }) = result_b {
            println!("  Matched with prefix_len={}, data={:?}", prefix_len, data);
        }
    }

    println!("SUCCESS: Stale NotFound did NOT persist across database instances");
}

/// Test the reverse scenario: cached positive result doesn't persist as false positive
///
/// 1. Open DB with IP -> query returns match (cached)
/// 2. Drop DB, open new DB WITHOUT the IP
/// 3. Query same IP -> should return NotFound, NOT stale match
#[test]
fn test_stale_match_does_not_persist() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let db_a_path = temp_dir.path().join("db_a_has_match.mxy");
    let db_b_path = temp_dir.path().join("db_b_no_match.mxy");

    let test_ip = "80.239.174.89";

    // Create DB_A: DOES contain the test IP
    {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut data = HashMap::new();
        data.insert(
            "name".to_string(),
            matchy_data_format::DataValue::String("matched".to_string()),
        );
        builder.add_entry("80.239.0.0/16", data).unwrap();
        let bytes = builder.build().unwrap();
        std::fs::write(&db_a_path, bytes).unwrap();
    }

    // Create DB_B: Does NOT contain the test IP
    {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut data = HashMap::new();
        data.insert(
            "name".to_string(),
            matchy_data_format::DataValue::String("other".to_string()),
        );
        builder.add_entry("1.1.1.0/24", data).unwrap();
        let bytes = builder.build().unwrap();
        std::fs::write(&db_b_path, bytes).unwrap();
    }

    // Step 1: Open DB_A and query the IP - should MATCH
    {
        let db_a = Database::open_with_options(DatabaseOptions {
            path: db_a_path.clone(),
            cache_capacity: Some(100), // Cache enabled!
            ..Default::default()
        })
        .expect("Failed to open DB_A");

        let result_a = db_a.lookup(test_ip).expect("Lookup failed");

        assert!(
            is_match(&result_a),
            "DB_A should match {}, but got: {:?}",
            test_ip,
            result_a
        );

        println!(
            "DB_A lookup for {}: {:?} (expected match)",
            test_ip, result_a
        );
    }

    // Step 2: Open DB_B and query the SAME IP - should NOT MATCH
    {
        let db_b = Database::open_with_options(DatabaseOptions {
            path: db_b_path.clone(),
            cache_capacity: Some(100), // Cache enabled!
            ..Default::default()
        })
        .expect("Failed to open DB_B");

        let result_b = db_b.lookup(test_ip).expect("Lookup failed");

        // THIS IS THE BUG (reverse case): If the cached match from DB_A persists,
        // this assertion will FAIL
        assert!(
            !is_match(&result_b),
            "BUG: DB_B should NOT match {} but got {:?} - stale match from DB_A persisted!",
            test_ip,
            result_b
        );

        println!(
            "DB_B lookup for {}: {:?} (expected NotFound)",
            test_ip, result_b
        );
    }

    println!("SUCCESS: Stale match did NOT persist across database instances");
}

/// Test that disabling cache works around the bug
#[test]
fn test_no_cache_works_correctly() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let db_a_path = temp_dir.path().join("db_a_no_match.mxy");
    let db_b_path = temp_dir.path().join("db_b_has_match.mxy");

    let test_ip = "80.239.174.89";

    // Create DB_A: Does NOT contain the test IP
    {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut data = HashMap::new();
        data.insert(
            "name".to_string(),
            matchy_data_format::DataValue::String("other".to_string()),
        );
        builder.add_entry("1.1.1.0/24", data).unwrap();
        let bytes = builder.build().unwrap();
        std::fs::write(&db_a_path, bytes).unwrap();
    }

    // Create DB_B: DOES contain the test IP
    {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut data = HashMap::new();
        data.insert(
            "name".to_string(),
            matchy_data_format::DataValue::String("matched".to_string()),
        );
        builder.add_entry("80.239.0.0/16", data).unwrap();
        let bytes = builder.build().unwrap();
        std::fs::write(&db_b_path, bytes).unwrap();
    }

    // With cache DISABLED, this should work correctly
    {
        let db_a = Database::open_with_options(DatabaseOptions {
            path: db_a_path.clone(),
            cache_capacity: Some(0), // Cache DISABLED
            ..Default::default()
        })
        .expect("Failed to open DB_A");

        let result_a = db_a.lookup(test_ip).expect("Lookup failed");
        assert!(!is_match(&result_a), "DB_A should NOT match");
    }

    {
        let db_b = Database::open_with_options(DatabaseOptions {
            path: db_b_path.clone(),
            cache_capacity: Some(0), // Cache DISABLED
            ..Default::default()
        })
        .expect("Failed to open DB_B");

        let result_b = db_b.lookup(test_ip).expect("Lookup failed");
        assert!(
            is_match(&result_b),
            "DB_B should match when cache is disabled"
        );
    }

    println!("SUCCESS: no_cache workaround works correctly");
}

/// Test WatchingDatabase cache generation doesn't conflict with global counter
///
/// Bug scenario:
/// 1. Regular Database A created -> gets generation N from global counter
/// 2. WatchingDatabase created -> gets generation N+1 from global counter  
/// 3. WatchingDatabase reloads -> uses its internal counter which may equal N
/// 4. Cache entries from Database A are returned for WatchingDatabase queries!
#[test]
fn test_watching_database_generation_conflict() {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let temp_dir = tempdir().expect("Failed to create temp dir");
    let regular_db_path = temp_dir.path().join("regular.mxy");
    let watching_db_path = temp_dir.path().join("watching.mxy");

    let test_ip = "80.239.174.89";

    // Create regular DB: Does NOT contain the test IP
    {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut data = HashMap::new();
        data.insert(
            "name".to_string(),
            matchy_data_format::DataValue::String("regular_no_match".to_string()),
        );
        builder.add_entry("1.1.1.0/24", data).unwrap();
        let bytes = builder.build().unwrap();
        std::fs::write(&regular_db_path, bytes).unwrap();
    }

    // Create watching DB: DOES contain the test IP
    {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut data = HashMap::new();
        data.insert(
            "name".to_string(),
            matchy_data_format::DataValue::String("watching_has_match".to_string()),
        );
        builder.add_entry("80.239.0.0/16", data).unwrap();
        let bytes = builder.build().unwrap();
        std::fs::write(&watching_db_path, bytes).unwrap();
    }

    // Step 1: Open regular database and query - should NOT match, caches NotFound
    let regular_db = Database::open_with_options(DatabaseOptions {
        path: regular_db_path.clone(),
        cache_capacity: Some(100),
        ..Default::default()
    })
    .expect("Failed to open regular DB");

    let result_regular = regular_db.lookup(test_ip).expect("Lookup failed");
    assert!(!is_match(&result_regular), "Regular DB should NOT match");
    println!("Regular DB lookup: {:?}", result_regular);

    // Step 2: Create WatchingDatabase and query - should MATCH
    let reload_count = Arc::new(AtomicU32::new(0));
    let reload_count_clone = reload_count.clone();

    let watching_db = matchy::WatchingDatabase::from(&watching_db_path)
        .on_reload(move |event| {
            if event.success {
                reload_count_clone.fetch_add(1, Ordering::Relaxed);
                println!("WatchingDB reloaded, generation={}", event.generation);
            }
        })
        .open()
        .expect("Failed to create WatchingDatabase");

    // Wait a bit for initial load
    thread::sleep(Duration::from_millis(100));

    let result_watching = watching_db.lookup(test_ip).expect("Query failed");

    // THIS IS THE CRITICAL TEST
    // If WatchingDatabase's cache generation conflicts with regular DB's generation,
    // we might get the cached NotFound from regular DB instead of the actual match
    assert!(
        is_match(&result_watching),
        "BUG: WatchingDatabase should match {} but got {:?} - possible generation conflict with regular DB!",
        test_ip, result_watching
    );

    println!("WatchingDB lookup: {:?}", result_watching);

    // Keep regular_db alive during test to ensure its cache entries persist
    drop(regular_db);

    drop(watching_db);

    println!("SUCCESS: WatchingDatabase generation doesn't conflict with regular Database");
}

/// Test that same file path reloaded gets fresh cache
/// This simulates Wireshark's reload scenario
#[test]
fn test_same_path_reload_gets_fresh_results() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("reloadable.mxy");

    let test_ip = "80.239.174.89";

    // Create initial DB: Does NOT contain the test IP
    {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut data = HashMap::new();
        data.insert(
            "name".to_string(),
            matchy_data_format::DataValue::String("initial".to_string()),
        );
        builder.add_entry("1.1.1.0/24", data).unwrap();
        let bytes = builder.build().unwrap();
        std::fs::write(&db_path, bytes).unwrap();
    }

    // Open and query - should NOT match
    {
        let db = Database::open_with_options(DatabaseOptions {
            path: db_path.clone(),
            cache_capacity: Some(100),
            ..Default::default()
        })
        .expect("Failed to open DB");

        let result = db.lookup(test_ip).expect("Lookup failed");
        assert!(!is_match(&result), "Initial DB should NOT match");
        println!("Initial lookup: {:?}", result);
    }

    // OVERWRITE the same file with new content that HAS the IP
    {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut data = HashMap::new();
        data.insert(
            "name".to_string(),
            matchy_data_format::DataValue::String("reloaded".to_string()),
        );
        builder.add_entry("80.239.0.0/16", data).unwrap();
        let bytes = builder.build().unwrap();
        std::fs::write(&db_path, bytes).unwrap();
    }

    // Reopen SAME PATH and query - should NOW match
    {
        let db = Database::open_with_options(DatabaseOptions {
            path: db_path.clone(),
            cache_capacity: Some(100),
            ..Default::default()
        })
        .expect("Failed to open reloaded DB");

        let result = db.lookup(test_ip).expect("Lookup failed");

        // THIS IS THE CRITICAL TEST for reload scenario
        assert!(
            is_match(&result),
            "BUG: Reloaded DB should match {} but got {:?} - stale cache from previous open!",
            test_ip,
            result
        );

        println!("Reloaded lookup: {:?}", result);
    }

    println!("SUCCESS: Same path reload gets fresh results");
}
