//! Built-in database schemas for yield value validation
//!
//! Matchy includes built-in schemas that define the structure of yield values
//! for common database types. These schemas enable validation during database
//! building to ensure data consistency.
//!
//! # Available Schemas
//!
//! - **threatdb** - Threat intelligence databases (ThreatDB-v1)
//!
//! # Usage
//!
//! When building via CLI, use a known database type:
//! ```bash
//! matchy build --database-type threatdb input.csv -o threats.mxy
//! ```
//!
//! Matchy recognizes `threatdb` as a built-in type and automatically:
//! - Validates yield values against the ThreatDB schema
//! - Sets the canonical `database_type` metadata to `ThreatDB-v1`
//!
//! Via the Rust API:
//! ```rust,ignore
//! use matchy::schemas::{get_schema_info, is_known_database_type};
//!
//! // Check if a database type has a known schema
//! if is_known_database_type("threatdb") {
//!     let info = get_schema_info("threatdb").unwrap();
//!     println!("Canonical type: {}", info.database_type); // "ThreatDB-v1"
//! }
//! ```

/// ThreatDB v1 schema - threat intelligence yield values
///
/// This schema defines the structure for threat intelligence databases,
/// compatible with MISP and STIX concepts.
pub const THREATDB_V1_SCHEMA: &str = include_str!("../../../../schemas/threatdb-v1.schema.json");

/// Schema name for ThreatDB
pub const THREATDB_NAME: &str = "threatdb";

/// Database type string for ThreatDB v1
pub const THREATDB_DATABASE_TYPE: &str = "ThreatDB-v1";

/// Information about a built-in schema
#[derive(Debug, Clone)]
pub struct SchemaInfo {
    /// Short name used in CLI (e.g., "threatdb")
    pub name: &'static str,
    /// Database type string set in metadata (e.g., "ThreatDB-v1")
    pub database_type: &'static str,
    /// Raw JSON Schema content
    pub schema_json: &'static str,
    /// Human-readable description
    pub description: &'static str,
}

/// All available built-in schemas
pub static SCHEMAS: &[SchemaInfo] = &[SchemaInfo {
    name: THREATDB_NAME,
    database_type: THREATDB_DATABASE_TYPE,
    schema_json: THREATDB_V1_SCHEMA,
    description: "Threat intelligence database with MISP/STIX-compatible fields",
}];

/// Get a schema by name
///
/// Accepts either the short name (e.g., "threatdb") or the canonical database_type
/// (e.g., "ThreatDB-v1").
///
/// # Arguments
/// * `name` - Schema name or database_type
///
/// # Returns
/// The raw JSON schema string, or None if not found
pub fn get_schema(name: &str) -> Option<&'static str> {
    SCHEMAS
        .iter()
        .find(|s| s.name == name || s.database_type == name)
        .map(|s| s.schema_json)
}

/// Get full schema info by name
///
/// # Arguments
/// * `name` - Schema name (e.g., "threatdb")
///
/// # Returns
/// The schema info, or None if not found
pub fn get_schema_info(name: &str) -> Option<&'static SchemaInfo> {
    SCHEMAS.iter().find(|s| s.name == name)
}

/// Get the database_type string for a schema
///
/// # Arguments
/// * `name` - Schema name (e.g., "threatdb")
///
/// # Returns
/// The database_type to use in metadata (e.g., "ThreatDB-v1"), or None if not found
pub fn schema_database_type(name: &str) -> Option<&'static str> {
    SCHEMAS
        .iter()
        .find(|s| s.name == name)
        .map(|s| s.database_type)
}

/// Detect schema name from a database_type string
///
/// # Arguments
/// * `database_type` - The database_type from metadata (e.g., "ThreatDB-v1")
///
/// # Returns
/// The schema name (e.g., "threatdb"), or None if not a known schema
pub fn detect_schema_from_database_type(database_type: &str) -> Option<&'static str> {
    SCHEMAS
        .iter()
        .find(|s| s.database_type == database_type)
        .map(|s| s.name)
}

/// List all available schema names
pub fn available_schemas() -> impl Iterator<Item = &'static str> {
    SCHEMAS.iter().map(|s| s.name)
}

/// Check if a database type name is a known built-in type with schema validation
///
/// Accepts either the short name (e.g., "threatdb") or the canonical database_type
/// (e.g., "ThreatDB-v1").
///
/// # Arguments
/// * `name` - Database type name
///
/// # Returns
/// true if this is a known type with built-in schema validation
pub fn is_known_database_type(name: &str) -> bool {
    SCHEMAS
        .iter()
        .any(|s| s.name == name || s.database_type == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threatdb_schema_embedded() {
        let schema = get_schema("threatdb").expect("threatdb schema should exist");
        assert!(schema.contains("ThreatDB Schema"));
        assert!(schema.contains("threat_level"));
        assert!(schema.contains("category"));
        assert!(schema.contains("source"));
    }

    #[test]
    fn test_schema_database_type() {
        assert_eq!(schema_database_type("threatdb"), Some("ThreatDB-v1"));
        assert_eq!(schema_database_type("nonexistent"), None);
    }

    #[test]
    fn test_detect_schema() {
        assert_eq!(
            detect_schema_from_database_type("ThreatDB-v1"),
            Some("threatdb")
        );
        assert_eq!(detect_schema_from_database_type("Unknown-Type"), None);
    }

    #[test]
    fn test_get_schema_by_database_type() {
        // Should be able to get schema by canonical database_type
        let schema = get_schema("ThreatDB-v1").expect("should find by database_type");
        assert!(schema.contains("ThreatDB Schema"));
    }

    #[test]
    fn test_is_known_database_type() {
        // Short name
        assert!(is_known_database_type("threatdb"));

        // Canonical type
        assert!(is_known_database_type("ThreatDB-v1"));

        // Unknown
        assert!(!is_known_database_type("Unknown-Type"));
    }

    #[test]
    fn test_available_schemas() {
        let schemas: Vec<_> = available_schemas().collect();
        assert!(schemas.contains(&"threatdb"));
        assert_eq!(schemas.len(), 1);
    }

    #[test]
    fn test_schema_info() {
        let info = get_schema_info("threatdb").expect("should exist");
        assert_eq!(info.name, "threatdb");
        assert_eq!(info.database_type, "ThreatDB-v1");
        assert!(info.description.contains("Threat intelligence"));
    }

    #[test]
    fn test_schema_is_valid_json() {
        let schema = get_schema("threatdb").unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(schema).expect("schema should be valid JSON");
        assert_eq!(parsed["title"], "ThreatDB Schema v1");
    }
}
