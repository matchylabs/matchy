//! Integration tests for schema validation during database building
//!
//! These tests verify that the CLI correctly validates yield values against
//! known schemas (like ThreatDB) when building databases.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Helper to create a matchy command
fn matchy_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("matchy"))
}

// =============================================================================
// JSON Format Tests
// =============================================================================

#[test]
fn test_build_threatdb_valid_json() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("data.json");
    let output_file = temp_dir.path().join("test.mxy");

    // Valid ThreatDB data - has all required fields
    let json = r#"[
        {"key": "evil.com", "data": {"threat_level": "high", "category": "malware", "source": "test-feed"}},
        {"key": "192.168.1.0/24", "data": {"threat_level": "medium", "category": "c2", "source": "internal"}},
        {"key": "*.bad-domain.org", "data": {"threat_level": "critical", "category": "phishing", "source": "abuse.ch"}}
    ]"#;
    fs::write(&input_file, json).unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("-f")
        .arg("json")
        .arg("--database-type")
        .arg("threatdb")
        .arg("-v")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Schema validation: enabled (ThreatDB-v1)",
        ))
        .stdout(predicate::str::contains("Database built"));
}

#[test]
fn test_build_threatdb_with_optional_fields() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("data.json");
    let output_file = temp_dir.path().join("test.mxy");

    // Valid ThreatDB data with optional fields
    let json = r#"[
        {
            "key": "evil.com",
            "data": {
                "threat_level": "high",
                "category": "malware",
                "source": "test-feed",
                "confidence": 85,
                "tlp": "AMBER",
                "description": "Known malware C2 server",
                "tags": ["emotet", "banking-trojan"]
            }
        }
    ]"#;
    fs::write(&input_file, json).unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("-f")
        .arg("json")
        .arg("--database-type")
        .arg("threatdb")
        .assert()
        .success();
}

#[test]
fn test_build_threatdb_invalid_threat_level() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("data.json");
    let output_file = temp_dir.path().join("test.mxy");

    // Invalid: threat_level has wrong enum value
    let json = r#"[
        {"key": "evil.com", "data": {"threat_level": "super-critical", "category": "malware", "source": "test"}}
    ]"#;
    fs::write(&input_file, json).unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("-f")
        .arg("json")
        .arg("--database-type")
        .arg("threatdb")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Schema validation failed"))
        .stderr(predicate::str::contains("evil.com"));
}

#[test]
fn test_build_threatdb_missing_required_field() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("data.json");
    let output_file = temp_dir.path().join("test.mxy");

    // Invalid: missing required fields (category and source)
    let json = r#"[
        {"key": "evil.com", "data": {"threat_level": "high"}}
    ]"#;
    fs::write(&input_file, json).unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("-f")
        .arg("json")
        .arg("--database-type")
        .arg("threatdb")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Schema validation failed"))
        .stderr(predicate::str::contains("required"));
}

#[test]
fn test_build_threatdb_invalid_confidence_range() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("data.json");
    let output_file = temp_dir.path().join("test.mxy");

    // Invalid: confidence > 100
    let json = r#"[
        {"key": "evil.com", "data": {"threat_level": "high", "category": "malware", "source": "test", "confidence": 150}}
    ]"#;
    fs::write(&input_file, json).unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("-f")
        .arg("json")
        .arg("--database-type")
        .arg("threatdb")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Schema validation failed"));
}

#[test]
fn test_build_threatdb_invalid_tlp() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("data.json");
    let output_file = temp_dir.path().join("test.mxy");

    // Invalid: tlp has wrong enum value
    let json = r#"[
        {"key": "evil.com", "data": {"threat_level": "high", "category": "malware", "source": "test", "tlp": "purple"}}
    ]"#;
    fs::write(&input_file, json).unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("-f")
        .arg("json")
        .arg("--database-type")
        .arg("threatdb")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Schema validation failed"));
}

// =============================================================================
// CSV Format Tests
// =============================================================================

#[test]
fn test_build_threatdb_valid_csv() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("data.csv");
    let output_file = temp_dir.path().join("test.mxy");

    // Valid ThreatDB CSV
    let csv = "key,threat_level,category,source\n\
               evil.com,high,malware,test-feed\n\
               192.168.1.0/24,medium,c2,internal\n";
    fs::write(&input_file, csv).unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("-f")
        .arg("csv")
        .arg("--database-type")
        .arg("threatdb")
        .arg("-v")
        .assert()
        .success()
        .stdout(predicate::str::contains("Schema validation: enabled"));
}

#[test]
fn test_build_threatdb_invalid_csv() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("data.csv");
    let output_file = temp_dir.path().join("test.mxy");

    // Invalid: threat_level has wrong value
    let csv = "key,threat_level,category,source\n\
               evil.com,super-bad,malware,test-feed\n";
    fs::write(&input_file, csv).unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("-f")
        .arg("csv")
        .arg("--database-type")
        .arg("threatdb")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Schema validation failed"));
}

// =============================================================================
// Custom Database Type (No Validation) Tests
// =============================================================================

#[test]
fn test_build_custom_type_no_validation() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("data.json");
    let output_file = temp_dir.path().join("test.mxy");

    // Data that wouldn't pass ThreatDB validation, but custom types don't validate
    let json = r#"[
        {"key": "evil.com", "data": {"arbitrary_field": "any_value", "number": 12345}}
    ]"#;
    fs::write(&input_file, json).unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("-f")
        .arg("json")
        .arg("--database-type")
        .arg("MyCustomType")
        .assert()
        .success();
}

#[test]
fn test_build_no_type_no_validation() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("data.json");
    let output_file = temp_dir.path().join("test.mxy");

    // Data without any schema - should succeed
    let json = r#"[
        {"key": "evil.com", "data": {"anything": "goes"}}
    ]"#;
    fs::write(&input_file, json).unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("-f")
        .arg("json")
        .assert()
        .success();
}

// =============================================================================
// Inspect Tests (verify database_type in metadata)
// =============================================================================

#[test]
fn test_inspect_shows_canonical_database_type() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("data.json");
    let output_file = temp_dir.path().join("test.mxy");

    // Build a valid ThreatDB database
    let json = r#"[
        {"key": "evil.com", "data": {"threat_level": "high", "category": "malware", "source": "test"}}
    ]"#;
    fs::write(&input_file, json).unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("-f")
        .arg("json")
        .arg("--database-type")
        .arg("threatdb")
        .assert()
        .success();

    // Inspect should show the canonical type "ThreatDB-v1"
    matchy_cmd()
        .arg("inspect")
        .arg(&output_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("ThreatDB-v1"));
}

// =============================================================================
// Additional Properties (Schema allows extra fields)
// =============================================================================

#[test]
fn test_build_threatdb_additional_properties_allowed() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("data.json");
    let output_file = temp_dir.path().join("test.mxy");

    // Schema has additionalProperties: true, so custom fields should be allowed
    let json = r#"[
        {
            "key": "evil.com",
            "data": {
                "threat_level": "high",
                "category": "malware",
                "source": "test",
                "custom_field": "custom_value",
                "internal_id": 12345
            }
        }
    ]"#;
    fs::write(&input_file, json).unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("-f")
        .arg("json")
        .arg("--database-type")
        .arg("threatdb")
        .assert()
        .success();
}

// =============================================================================
// Text format with validation (should fail - text has no yield data)
// =============================================================================

#[test]
fn test_build_threatdb_text_format_fails() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    // Text format has empty data - won't pass ThreatDB schema (missing required fields)
    fs::write(&input_file, "evil.com\n192.168.1.1\n").unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("-f")
        .arg("text")
        .arg("--database-type")
        .arg("threatdb")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Schema validation failed"))
        .stderr(predicate::str::contains("required"));
}

// =============================================================================
// Validate Command - Schema Validation Tests
// =============================================================================

#[test]
fn test_validate_threatdb_valid_entries() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("data.json");
    let output_file = temp_dir.path().join("test.mxy");

    // Build a valid ThreatDB database
    let json = r#"[
        {"key": "evil.com", "data": {"threat_level": "high", "category": "malware", "source": "test"}},
        {"key": "192.168.1.0/24", "data": {"threat_level": "medium", "category": "c2", "source": "internal"}}
    ]"#;
    fs::write(&input_file, json).unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("-f")
        .arg("json")
        .arg("--database-type")
        .arg("threatdb")
        .assert()
        .success();

    // Validate should pass and show schema validation info
    matchy_cmd()
        .arg("validate")
        .arg(&output_file)
        .arg("--level")
        .arg("strict")
        .arg("-v")
        .assert()
        .success()
        .stdout(predicate::str::contains("ThreatDB-v1"))
        .stdout(predicate::str::contains("schema"));
}

#[test]
fn test_validate_json_output_includes_schema_stats() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("data.json");
    let output_file = temp_dir.path().join("test.mxy");

    // Build a valid ThreatDB database
    let json = r#"[
        {"key": "evil.com", "data": {"threat_level": "high", "category": "malware", "source": "test"}}
    ]"#;
    fs::write(&input_file, json).unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("-f")
        .arg("json")
        .arg("--database-type")
        .arg("threatdb")
        .assert()
        .success();

    // Validate with JSON output - should include schema stats
    matchy_cmd()
        .arg("validate")
        .arg(&output_file)
        .arg("--json")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "\"database_type\": \"ThreatDB-v1\"",
        ))
        .stdout(predicate::str::contains("\"schema_validated\":"))
        .stdout(predicate::str::contains("\"schema_entries_checked\":"))
        .stdout(predicate::str::contains("\"schema_validation_failures\":"));
}

#[test]
fn test_validate_non_schema_database_no_schema_validation() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("data.json");
    let output_file = temp_dir.path().join("test.mxy");

    // Build a database without a known schema type
    let json = r#"[
        {"key": "evil.com", "data": {"custom": "data"}}
    ]"#;
    fs::write(&input_file, json).unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("-f")
        .arg("json")
        .assert()
        .success();

    // Validate with JSON output - schema_validated should be false
    matchy_cmd()
        .arg("validate")
        .arg(&output_file)
        .arg("--json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"schema_validated\": false"));
}
