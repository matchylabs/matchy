use matchy::{DataValue, Database, DatabaseBuilder, MatchMode, WatchingDatabase};
use std::collections::HashMap;
use std::fs;
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

#[test]
fn test_auto_reload_basic() {
    // Create a temporary database file in current directory (not /tmp)
    // System temp dirs like /var/folders may not be watchable on macOS
    // Use a regular directory (not hidden) for better FSEvents compatibility
    let temp_dir = tempfile::Builder::new()
        .prefix("test_matchy_")
        .tempdir_in(".")
        .unwrap();
    let db_path = temp_dir.path().join("test.mxy");

    // Build initial database with one entry
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
    let mut data1 = HashMap::new();
    data1.insert("value".to_string(), DataValue::String("first".to_string()));
    builder.add_entry("1.2.3.4", data1).unwrap();
    let db_bytes = builder.build().unwrap();
    fs::write(&db_path, &db_bytes).unwrap();

    // Open with WatchingDatabase for auto-reload
    let db = WatchingDatabase::from(&db_path).open().unwrap();

    // Give watcher thread time to fully initialize and start watching
    thread::sleep(Duration::from_millis(500));

    // Query should find first value
    let result = db.lookup("1.2.3.4").unwrap();
    assert!(result.is_some());

    // Update the database file using atomic rename
    let mut builder2 = DatabaseBuilder::new(MatchMode::CaseSensitive);
    let mut data2 = HashMap::new();
    data2.insert("value".to_string(), DataValue::String("second".to_string()));
    builder2.add_entry("1.2.3.4", data2).unwrap();
    let db_bytes2 = builder2.build().unwrap();

    // Write to temp file then atomically rename (proper way to update databases)
    let temp_new_path = temp_dir.path().join("test_new.mxy");
    fs::write(&temp_new_path, &db_bytes2).unwrap();
    fs::rename(&temp_new_path, &db_path).unwrap();

    // Wait for reload with retry (file watching can be timing-sensitive)
    let initial_generation = db.generation();
    let mut reloaded = false;
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(100));
        if db.generation() > initial_generation {
            reloaded = true;
            break;
        }
    }
    assert!(reloaded, "Database should have reloaded (generation should have increased)");

    // Query should now find updated value
    let result = db.lookup("1.2.3.4").unwrap();
    if let Some(matchy::QueryResult::Ip { data, .. }) = result {
        if let DataValue::Map(map) = data {
            if let Some(DataValue::String(s)) = map.get("value") {
                assert_eq!(s, "second", "Database should have reloaded with new data");
            } else {
                panic!("Expected string value");
            }
        } else {
            panic!("Expected map data");
        }
    } else {
        panic!("Expected IP result");
    }
}

#[test]
fn test_no_auto_reload_without_flag() {
    // Verify that databases DON'T auto-reload when flag is not set
    let temp_file = NamedTempFile::new().unwrap();
    let db_path = temp_file.path();

    // Build initial database
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
    let mut data1 = HashMap::new();
    data1.insert("value".to_string(), DataValue::String("first".to_string()));
    builder.add_entry("1.2.3.4", data1).unwrap();
    let db_bytes = builder.build().unwrap();
    fs::write(db_path, &db_bytes).unwrap();

    // Open WITHOUT auto-reload
    let db = Database::from(db_path).open().unwrap();

    // Update the database file using atomic rename
    let mut builder2 = DatabaseBuilder::new(MatchMode::CaseSensitive);
    let mut data2 = HashMap::new();
    data2.insert("value".to_string(), DataValue::String("second".to_string()));
    builder2.add_entry("1.2.3.4", data2).unwrap();
    let db_bytes2 = builder2.build().unwrap();

    // Write to temp file then atomically rename
    let temp_new = NamedTempFile::new().unwrap();
    fs::write(temp_new.path(), &db_bytes2).unwrap();
    fs::rename(temp_new.path(), db_path).unwrap();

    // Wait a bit
    thread::sleep(Duration::from_millis(500));

    // Should still see OLD data (no reload)
    let result = db.lookup("1.2.3.4").unwrap();
    if let Some(matchy::QueryResult::Ip {
        data: DataValue::Map(map),
        ..
    }) = result
    {
        if let Some(DataValue::String(s)) = map.get("value") {
            assert_eq!(
                s, "first",
                "Database should NOT have reloaded without auto_reload flag"
            );
        }
    }
}
