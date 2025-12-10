//! Extension traits for DatabaseBuilder with schema support
//!
//! This module provides the [`DatabaseBuilderExt`] trait which adds schema-aware
//! building capabilities to [`DatabaseBuilder`].
//!
//! # Example
//!
//! ```rust,ignore
//! use matchy::{DatabaseBuilder, DatabaseBuilderExt, MatchMode, DataValue};
//! use std::collections::HashMap;
//!
//! // Create a builder with ThreatDB schema validation
//! let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive)
//!     .with_schema("threatdb")?;
//!
//! // Entries are automatically validated against the schema
//! let mut data = HashMap::new();
//! data.insert("threat_level".to_string(), DataValue::String("high".to_string()));
//! data.insert("category".to_string(), DataValue::String("malware".to_string()));
//! data.insert("source".to_string(), DataValue::String("abuse.ch".to_string()));
//!
//! builder.add_entry("1.2.3.4", data)?;  // Validated!
//!
//! // Invalid data will fail
//! let mut bad_data = HashMap::new();
//! bad_data.insert("threat_level".to_string(), DataValue::String("invalid".to_string()));
//! // builder.add_entry("2.3.4.5", bad_data)?;  // Error: invalid threat_level
//! ```

use crate::schema_validation::{SchemaError, SchemaValidator};
use crate::schemas::get_schema_info;
use matchy_format::DatabaseBuilder;

/// Extension trait for [`DatabaseBuilder`] that adds schema support
///
/// This trait provides the [`with_schema`](DatabaseBuilderExt::with_schema) method
/// which enables automatic validation of entries against a built-in schema.
pub trait DatabaseBuilderExt: Sized {
    /// Configure the builder to validate entries against a built-in schema
    ///
    /// When a schema is configured:
    /// 1. All entries added via `add_entry()`, `add_ip()`, `add_literal()`, or `add_glob()`
    ///    will be validated against the schema before insertion
    /// 2. The `database_type` metadata will be automatically set to the schema's canonical type
    /// 3. Invalid entries will cause the add method to return an error
    ///
    /// # Arguments
    /// * `schema_name` - Name of a built-in schema (e.g., "threatdb")
    ///
    /// # Returns
    /// * `Ok(Self)` - Builder configured with schema validation
    /// * `Err(SchemaError)` - If the schema name is unknown or invalid
    ///
    /// # Available Schemas
    ///
    /// | Name | Database Type | Description |
    /// |------|---------------|-------------|
    /// | `threatdb` | `ThreatDB-v1` | Threat intelligence with MISP/STIX-compatible fields |
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use matchy::{DatabaseBuilder, DatabaseBuilderExt, MatchMode};
    ///
    /// let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive)
    ///     .with_schema("threatdb")?;
    ///
    /// // Now all entries will be validated against ThreatDB schema
    /// ```
    fn with_schema(self, schema_name: &str) -> Result<Self, SchemaError>;
}

impl DatabaseBuilderExt for DatabaseBuilder {
    fn with_schema(self, schema_name: &str) -> Result<Self, SchemaError> {
        let validator = SchemaValidator::new(schema_name)?;

        // Get the canonical database_type from schema info, or fall back to schema name
        let db_type = get_schema_info(schema_name)
            .map(|info| info.database_type)
            .unwrap_or(schema_name);

        Ok(self
            .with_database_type(db_type)
            .with_validator(Box::new(validator)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use matchy_data_format::DataValue;
    use matchy_match_mode::MatchMode;
    use std::collections::HashMap;

    fn valid_threatdb_data() -> HashMap<String, DataValue> {
        let mut data = HashMap::new();
        data.insert(
            "threat_level".to_string(),
            DataValue::String("high".to_string()),
        );
        data.insert(
            "category".to_string(),
            DataValue::String("malware".to_string()),
        );
        data.insert(
            "source".to_string(),
            DataValue::String("abuse.ch".to_string()),
        );
        data
    }

    #[test]
    fn test_with_schema_creates_validator() {
        let builder = DatabaseBuilder::new(MatchMode::CaseSensitive)
            .with_schema("threatdb")
            .expect("should create builder with schema");

        // We can't easily inspect the validator, but we can verify it was created
        // by trying to add an entry
        let mut builder = builder;
        let data = valid_threatdb_data();
        assert!(builder.add_entry("1.2.3.4", data).is_ok());
    }

    #[test]
    fn test_with_schema_unknown() {
        let result = DatabaseBuilder::new(MatchMode::CaseSensitive).with_schema("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_with_schema_validates_entries() {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive)
            .with_schema("threatdb")
            .expect("should create builder");

        // Valid entry should succeed
        let valid_data = valid_threatdb_data();
        assert!(builder.add_entry("1.2.3.4", valid_data).is_ok());

        // Invalid entry should fail
        let mut invalid_data = HashMap::new();
        invalid_data.insert(
            "threat_level".to_string(),
            DataValue::String("super-critical".to_string()), // Invalid enum
        );
        let result = builder.add_entry("2.3.4.5", invalid_data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Validation error"));
    }

    #[test]
    fn test_with_schema_validates_all_add_methods() {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive)
            .with_schema("threatdb")
            .expect("should create builder");

        let valid_data = valid_threatdb_data();

        // Test add_ip
        assert!(builder.add_ip("10.0.0.1", valid_data.clone()).is_ok());

        // Test add_literal
        assert!(builder
            .add_literal("evil.example.com", valid_data.clone())
            .is_ok());

        // Test add_glob
        assert!(builder.add_glob("*.evil.com", valid_data.clone()).is_ok());

        // All should fail with invalid data
        let invalid_data = HashMap::new(); // Missing required fields

        assert!(builder.add_ip("10.0.0.2", invalid_data.clone()).is_err());
        assert!(builder
            .add_literal("bad.example.com", invalid_data.clone())
            .is_err());
        assert!(builder.add_glob("*.bad.com", invalid_data.clone()).is_err());
    }

    #[test]
    fn test_builder_without_schema_no_validation() {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

        // Without schema, any data should be accepted
        let empty_data = HashMap::new();
        assert!(builder.add_entry("1.2.3.4", empty_data).is_ok());

        let mut arbitrary_data = HashMap::new();
        arbitrary_data.insert("foo".to_string(), DataValue::String("bar".to_string()));
        assert!(builder.add_entry("2.3.4.5", arbitrary_data).is_ok());
    }
}
