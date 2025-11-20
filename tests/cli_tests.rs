use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Helper to create a matchy command
fn matchy_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("matchy"))
}

#[test]
fn test_help() {
    matchy_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "High-performance unified database",
        ));
}

#[test]
fn test_version() {
    matchy_cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("matchy"));
}

#[test]
fn test_build_help() {
    matchy_cmd()
        .arg("build")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Build a unified database"));
}

#[test]
fn test_query_help() {
    matchy_cmd()
        .arg("query")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Query a pattern database"));
}

#[test]
fn test_inspect_help() {
    matchy_cmd()
        .arg("inspect")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Inspect a pattern database"));
}

#[test]
fn test_validate_help() {
    matchy_cmd()
        .arg("validate")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Validate a database file"));
}

#[test]
fn test_match_help() {
    matchy_cmd()
        .arg("match")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Match patterns against log files"));
}

#[test]
fn test_bench_help() {
    matchy_cmd()
        .arg("bench")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Benchmark database performance"));
}

#[test]
fn test_build_text_format() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    // Create input file with patterns
    fs::write(&input_file, "192.168.1.0/24\n*.evil.com\nexample.com\n").unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("--format")
        .arg("text")
        .assert()
        .success()
        .stdout(predicate::str::contains("Database built"));

    // Verify output file exists
    assert!(output_file.exists());
    assert!(output_file.metadata().unwrap().len() > 0);
}

#[test]
fn test_build_with_metadata() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    fs::write(&input_file, "*.malware.com\n").unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("--database-type")
        .arg("Test-Threats")
        .arg("--description")
        .arg("Test database")
        .arg("--desc-lang")
        .arg("en")
        .assert()
        .success();

    assert!(output_file.exists());
}

#[test]
fn test_build_case_insensitive() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    fs::write(&input_file, "*.EVIL.COM\n").unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("--case-insensitive")
        .assert()
        .success();

    assert!(output_file.exists());
}

#[test]
fn test_inspect_database() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    // Build database
    fs::write(&input_file, "192.168.1.0/24\n*.evil.com\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    // Inspect it
    matchy_cmd()
        .arg("inspect")
        .arg(&output_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("Database:"))
        .stdout(predicate::str::contains("Capabilities:"));
}

#[test]
fn test_inspect_json() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    fs::write(&input_file, "*.test.com\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    matchy_cmd()
        .arg("inspect")
        .arg(&output_file)
        .arg("--json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"has_glob_data\":"));
}

#[test]
fn test_query_pattern_match() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    // Build database with patterns
    fs::write(&input_file, "*.evil.com\nmalware.*.org\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    // Query should match
    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("subdomain.evil.com")
        .assert()
        .success();
}

#[test]
fn test_query_pattern_no_match() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    fs::write(&input_file, "*.evil.com\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    // Query should not match - exit code 1
    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("good.example.com")
        .assert()
        .code(1)
        .stdout(predicate::str::contains("[]"));
}

#[test]
fn test_query_quiet_mode() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    fs::write(&input_file, "*.test.com\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    // Quiet mode: no output, just exit code
    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("sub.test.com")
        .arg("--quiet")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());

    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("nomatch.com")
        .arg("--quiet")
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty());
}

#[test]
fn test_query_ip_address() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("ips.txt");
    let output_file = temp_dir.path().join("test.mxy");

    // Build database with IP ranges
    fs::write(&input_file, "192.168.1.0/24\n10.0.0.0/8\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    // Query IP - should match
    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("192.168.1.50")
        .assert()
        .success()
        .stdout(predicate::str::contains("192.168.1.0/24"));

    // Query IP - should not match
    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("8.8.8.8")
        .assert()
        .code(1);
}

#[test]
fn test_validate_database() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    // Use a combined database (IP + patterns) for better validation coverage
    fs::write(&input_file, "192.168.1.0/24\n*.test.com\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    // Validate with default (strict) level - should pass or have warnings only
    let output = matchy_cmd().arg("validate").arg(&output_file).assert();

    // Check that validation completed (might pass or fail, but should run)
    output.stdout(predicate::str::contains("Validating:"));
}

#[test]
fn test_validate_levels() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    // Use combined database for better validation
    fs::write(&input_file, "192.168.1.0/24\n*.test.com\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    // Test different validation levels - they should at least run
    for level in &["standard", "strict", "audit"] {
        matchy_cmd()
            .arg("validate")
            .arg(&output_file)
            .arg("--level")
            .arg(level)
            .assert()
            .stdout(predicate::str::contains("Validating:"));
    }
}

#[test]
fn test_validate_json_output() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    // Use combined database
    fs::write(&input_file, "192.168.1.0/24\n*.test.com\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    matchy_cmd()
        .arg("validate")
        .arg(&output_file)
        .arg("--json")
        .assert()
        .stdout(predicate::str::contains("\"is_valid\":"))
        .stdout(predicate::str::contains("\"validation_level\":"));
}

#[test]
fn test_match_stdin() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    // Build database with patterns that will be extracted from logs
    fs::write(&input_file, "*.evil.com\n*.malware.org\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    // Match command with stdin - using domain patterns that will be extracted
    let log_data =
        "user logged in from bad.evil.com\nsafe traffic\nconnection to threat.malware.org\n";

    matchy_cmd()
        .arg("match")
        .arg(&output_file)
        .arg("-")
        .arg("--format")
        .arg("json")
        .write_stdin(log_data)
        .assert()
        .success()
        .stdout(predicate::str::contains("evil.com"))
        .stdout(predicate::str::contains("malware.org"));
}

#[test]
fn test_build_csv_format() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("data.csv");
    let output_file = temp_dir.path().join("test.mxy");

    // Create CSV with entry and metadata
    let csv_content =
        "entry,severity,category\n*.evil.com,high,malware\n192.168.1.0/24,medium,suspicious\n";
    fs::write(&input_file, csv_content).unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("--format")
        .arg("csv")
        .assert()
        .success();

    assert!(output_file.exists());
}

#[test]
fn test_build_json_format() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("data.json");
    let output_file = temp_dir.path().join("test.mxy");

    // Create JSON input
    let json_content = r#"[
        {"key": "*.malware.com", "data": {"severity": "high"}},
        {"key": "192.168.1.0/24", "data": {"type": "suspicious"}}
    ]"#;
    fs::write(&input_file, json_content).unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("--format")
        .arg("json")
        .assert()
        .success();

    assert!(output_file.exists());
}

#[test]
fn test_build_verbose_output() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    fs::write(&input_file, "*.test.com\n").unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("--verbose")
        .assert()
        .success()
        .stdout(predicate::str::contains("Building database:"))
        .stdout(predicate::str::contains("Total entries:"));
}

#[test]
fn test_missing_database_file() {
    matchy_cmd()
        .arg("query")
        .arg("/nonexistent/database.mxy")
        .arg("test")
        .assert()
        .failure();
}

#[test]
fn test_invalid_format() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    fs::write(&input_file, "test\n").unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .arg("--format")
        .arg("invalid-format")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unknown format"));
}

#[test]
fn test_combined_database() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("combined.txt");
    let output_file = temp_dir.path().join("test.mxy");

    // Mix of IPs, patterns, and literals
    let content = "192.168.1.0/24\n*.evil.com\nexact-match.com\n10.0.0.0/8\nmalware-*.net\n";
    fs::write(&input_file, content).unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    // Query IP
    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("192.168.1.100")
        .assert()
        .success();

    // Query pattern
    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("sub.evil.com")
        .assert()
        .success();

    // Query literal
    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("exact-match.com")
        .assert()
        .success();
}

#[test]
fn test_bench_ip() {
    matchy_cmd()
        .arg("bench")
        .arg("ip")
        .arg("-n")
        .arg("100") // Small count for fast test
        .arg("--query-count")
        .arg("100")
        .arg("--load-iterations")
        .arg("1")
        .assert()
        .success()
        .stdout(predicate::str::contains("Benchmark complete"));
}

#[test]
fn test_bench_literal() {
    matchy_cmd()
        .arg("bench")
        .arg("literal")
        .arg("-n")
        .arg("100")
        .arg("--query-count")
        .arg("100")
        .arg("--load-iterations")
        .arg("1")
        .assert()
        .success()
        .stdout(predicate::str::contains("Benchmark complete"));
}

#[test]
fn test_bench_pattern() {
    matchy_cmd()
        .arg("bench")
        .arg("pattern")
        .arg("-n")
        .arg("100")
        .arg("--query-count")
        .arg("100")
        .arg("--load-iterations")
        .arg("1")
        .arg("--pattern-style")
        .arg("prefix")
        .assert()
        .success()
        .stdout(predicate::str::contains("Benchmark complete"));
}

#[test]
fn test_cli_argument_order() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let output_file = temp_dir.path().join("test.mxy");

    fs::write(&input_file, "*.test.com\n").unwrap();

    // Arguments in different orders should work
    matchy_cmd()
        .arg("build")
        .arg("-o")
        .arg(&output_file)
        .arg(&input_file)
        .arg("--format")
        .arg("text")
        .assert()
        .success();
}

#[test]
fn test_multiple_input_files() {
    let temp_dir = TempDir::new().unwrap();
    let input1 = temp_dir.path().join("patterns1.txt");
    let input2 = temp_dir.path().join("patterns2.txt");
    let output_file = temp_dir.path().join("test.mxy");

    fs::write(&input1, "*.evil1.com\n").unwrap();
    fs::write(&input2, "*.evil2.com\n").unwrap();

    matchy_cmd()
        .arg("build")
        .arg(&input1)
        .arg(&input2)
        .arg("-o")
        .arg(&output_file)
        .assert()
        .success();

    // Both patterns should be in the database
    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("sub.evil1.com")
        .assert()
        .success();

    matchy_cmd()
        .arg("query")
        .arg(&output_file)
        .arg("sub.evil2.com")
        .assert()
        .success();
}

#[test]
fn test_json_output_includes_match_data() {
    // Verify JSON output includes core match fields
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("ips.txt");
    let db_file = temp_dir.path().join("test.mxy");
    let log_file = temp_dir.path().join("test.log");

    // Build database with an IP
    fs::write(&input_file, "192.168.1.100/32\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&db_file)
        .assert()
        .success();

    // Create log file with known content
    let test_line = "2024-01-15 Connection from 192.168.1.100 detected";
    fs::write(&log_file, format!("{}\n", test_line)).unwrap();

    // Run match with JSON output
    let output = matchy_cmd()
        .arg("match")
        .arg(&db_file)
        .arg(&log_file)
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).unwrap();
    let json_lines: Vec<&str> = stdout.lines().collect();
    assert!(!json_lines.is_empty(), "Expected JSON output");

    // Parse the JSON and verify core match fields
    let json: serde_json::Value =
        serde_json::from_str(json_lines[0]).expect("Failed to parse JSON output");

    // Verify essential fields are present
    let matched_text = json
        .get("matched_text")
        .expect("JSON missing 'matched_text' field")
        .as_str()
        .expect("matched_text should be a string");

    assert_eq!(matched_text, "192.168.1.100", "Should match the IP address");

    // Verify source and match_type fields
    assert!(
        json.get("source").is_some(),
        "JSON should include source field"
    );
    assert!(
        json.get("match_type").is_some(),
        "JSON should include match_type field"
    );
}

#[test]
fn test_json_output_parallel_mode() {
    // Verify JSON output works correctly in parallel mode
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("patterns.txt");
    let db_file = temp_dir.path().join("test.mxy");
    let log_file = temp_dir.path().join("test.log");

    // Build database
    fs::write(&input_file, "*.malware.com\n").unwrap();
    matchy_cmd()
        .arg("build")
        .arg(&input_file)
        .arg("-o")
        .arg(&db_file)
        .assert()
        .success();

    // Create log with multiple lines
    let target_line = "Line 2: Request to bad.malware.com blocked";
    fs::write(
        &log_file,
        format!(
            "Line 1: Normal traffic\n{}\nLine 3: More content\n",
            target_line
        ),
    )
    .unwrap();

    // Run with parallel mode
    let output = matchy_cmd()
        .arg("match")
        .arg(&db_file)
        .arg(&log_file)
        .arg("--format")
        .arg("json")
        .arg("--threads")
        .arg("4")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).unwrap();
    let first_line = stdout.lines().next().unwrap();
    let json: serde_json::Value = serde_json::from_str(first_line).expect("Failed to parse JSON");

    // Verify essential fields are present
    let matched_text = json["matched_text"].as_str().unwrap();
    assert_eq!(
        matched_text, "bad.malware.com",
        "Parallel mode should find the domain match"
    );

    // Verify standard output fields
    assert!(
        json.get("source").is_some(),
        "JSON should include source field"
    );
    assert!(
        json.get("match_type").is_some(),
        "JSON should include match_type field"
    );
}
