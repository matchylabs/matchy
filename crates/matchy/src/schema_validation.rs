//! Schema validation for yield values
//!
//! Validates that database yield values conform to a JSON Schema during building.
//! This ensures data consistency and enables consumers to rely on the structure
//! of yield values without runtime validation.
//!
//! # Example
//!
//! ```rust,ignore
//! use matchy::schema_validation::SchemaValidator;
//! use matchy::DataValue;
//! use std::collections::HashMap;
//!
//! // Create validator for ThreatDB schema
//! let validator = SchemaValidator::new("threatdb")?;
//!
//! // Validate a yield value
//! let mut data = HashMap::new();
//! data.insert("threat_level".to_string(), DataValue::String("high".to_string()));
//! data.insert("category".to_string(), DataValue::String("malware".to_string()));
//! data.insert("source".to_string(), DataValue::String("abuse.ch".to_string()));
//!
//! validator.validate(&data)?; // Ok
//! ```

use crate::schemas::{get_schema, get_schema_info};
use jsonschema::Validator;
use matchy_data_format::DataValue;
use matchy_format::EntryValidator;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use thiserror::Error;

/// Error returned when schema validation fails
#[derive(Debug, Clone)]
pub struct SchemaValidationError {
    /// List of validation errors
    pub errors: Vec<ValidationErrorDetail>,
}

impl fmt::Display for SchemaValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.errors.len() == 1 {
            write!(f, "Schema validation failed: {}", self.errors[0])
        } else {
            writeln!(
                f,
                "Schema validation failed with {} errors:",
                self.errors.len()
            )?;
            for (i, err) in self.errors.iter().enumerate() {
                writeln!(f, "  {}. {}", i + 1, err)?;
            }
            Ok(())
        }
    }
}

impl std::error::Error for SchemaValidationError {}

/// Detail about a single validation error
#[derive(Debug, Clone)]
pub struct ValidationErrorDetail {
    /// JSON path to the invalid field (e.g., "/threat_level" or "/confidence")
    pub path: String,
    /// Description of what's wrong
    pub message: String,
}

impl fmt::Display for ValidationErrorDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() || self.path == "/" {
            write!(f, "{}", self.message)
        } else {
            write!(f, "{}: {}", self.path, self.message)
        }
    }
}

/// Errors that can occur when creating or using a schema validator
#[derive(Debug, Error)]
pub enum SchemaError {
    /// Unknown schema name
    #[error("Unknown database type: '{0}'. Known types with validation: {1}")]
    UnknownSchema(String, String),

    /// Failed to parse schema JSON
    #[error("Failed to parse schema JSON: {0}")]
    InvalidSchemaJson(#[from] serde_json::Error),

    /// Failed to compile schema
    #[error("Failed to compile JSON Schema: {0}")]
    SchemaCompileError(String),
}

/// Validates yield values against a JSON Schema
///
/// The validator stores the parsed schema JSON and creates a compiled validator
/// on each validation call. This is necessary because `jsonschema::Validator`
/// uses `Rc` internally and is not `Send + Sync`, but `EntryValidator` requires
/// thread safety for use with `DatabaseBuilder`.
///
/// The schema compilation is fast enough that this approach is acceptable for
/// build-time validation where correctness matters more than raw performance.
pub struct SchemaValidator {
    schema: serde_json::Value,
    schema_name: String,
}

impl std::fmt::Debug for SchemaValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchemaValidator")
            .field("schema_name", &self.schema_name)
            .finish_non_exhaustive()
    }
}

impl SchemaValidator {
    /// Create a new validator for a built-in database type
    ///
    /// # Arguments
    /// * `database_type` - Name of a built-in database type (e.g., "threatdb")
    ///
    /// # Returns
    /// A compiled validator, or an error if the type is unknown or invalid
    ///
    /// # Example
    /// ```rust,ignore
    /// let validator = SchemaValidator::new("threatdb")?;
    /// ```
    pub fn new(database_type: &str) -> Result<Self, SchemaError> {
        let schema_json = get_schema(database_type).ok_or_else(|| {
            let available: Vec<_> = crate::schemas::available_schemas().collect();
            SchemaError::UnknownSchema(database_type.to_string(), available.join(", "))
        })?;

        Self::from_json(database_type, schema_json)
    }

    /// Create a validator from raw JSON Schema
    ///
    /// # Arguments
    /// * `name` - Name for error messages
    /// * `schema_json` - Raw JSON Schema string
    pub fn from_json(name: &str, schema_json: &str) -> Result<Self, SchemaError> {
        let schema: serde_json::Value = serde_json::from_str(schema_json)?;

        // Validate that the schema compiles successfully
        Validator::new(&schema).map_err(|e| SchemaError::SchemaCompileError(e.to_string()))?;

        Ok(Self {
            schema,
            schema_name: name.to_string(),
        })
    }

    /// Create a compiled validator for this schema
    ///
    /// This is called internally for each validation. The jsonschema crate's
    /// Validator is not Send+Sync, so we create it fresh each time.
    fn create_validator(&self) -> Validator {
        // This should never fail since we validated the schema in from_json()
        Validator::new(&self.schema).expect("schema was validated at construction time")
    }

    /// Get the schema name
    pub fn schema_name(&self) -> &str {
        &self.schema_name
    }

    /// Get the canonical database_type that should be set in metadata
    ///
    /// Returns None if this validator was created from custom JSON (not a built-in type)
    pub fn database_type(&self) -> Option<&'static str> {
        get_schema_info(&self.schema_name).map(|info| info.database_type)
    }

    /// Validate a yield value (HashMap of field name to DataValue)
    ///
    /// # Arguments
    /// * `data` - The yield value to validate
    ///
    /// # Returns
    /// Ok(()) if valid, or SchemaValidationError with details
    pub fn validate(&self, data: &HashMap<String, DataValue>) -> Result<(), SchemaValidationError> {
        // Convert DataValue map to serde_json::Value for validation
        let json_value = data_map_to_json(data)?;

        let validator = self.create_validator();

        // Run validation
        let result = validator.validate(&json_value);

        if result.is_ok() {
            Ok(())
        } else {
            let errors: Vec<ValidationErrorDetail> = validator
                .iter_errors(&json_value)
                .map(|err| ValidationErrorDetail {
                    path: err.instance_path().to_string(),
                    message: err.to_string(),
                })
                .collect();

            Err(SchemaValidationError { errors })
        }
    }

    /// Validate and return a detailed result (useful for collecting all errors)
    pub fn validate_detailed(
        &self,
        data: &HashMap<String, DataValue>,
    ) -> Vec<ValidationErrorDetail> {
        match data_map_to_json(data) {
            Ok(json_value) => {
                let validator = self.create_validator();
                validator
                    .iter_errors(&json_value)
                    .map(|err| ValidationErrorDetail {
                        path: err.instance_path().to_string(),
                        message: err.to_string(),
                    })
                    .collect()
            }
            Err(e) => vec![ValidationErrorDetail {
                path: String::new(),
                message: format!("Failed to convert data: {}", e),
            }],
        }
    }
}

/// Convert a DataValue map to serde_json::Value for schema validation
fn data_map_to_json(
    data: &HashMap<String, DataValue>,
) -> Result<serde_json::Value, SchemaValidationError> {
    // DataValue implements Serialize, so we can use serde_json
    serde_json::to_value(data).map_err(|e| SchemaValidationError {
        errors: vec![ValidationErrorDetail {
            path: String::new(),
            message: format!("Failed to serialize data for validation: {}", e),
        }],
    })
}

/// Implement EntryValidator trait for SchemaValidator
///
/// This allows SchemaValidator to be used with DatabaseBuilder::with_validator()
/// for automatic schema validation during database construction.
impl EntryValidator for SchemaValidator {
    fn validate(
        &self,
        key: &str,
        data: &HashMap<String, DataValue>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.validate(data).map_err(|e| {
            let error_msg = format!("Entry '{}': {}", key, e);
            Box::new(SchemaValidationError {
                errors: vec![ValidationErrorDetail {
                    path: String::new(),
                    message: error_msg,
                }],
            }) as Box<dyn Error + Send + Sync>
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_validator_creation() {
        let validator = SchemaValidator::new("threatdb").expect("should create validator");
        assert_eq!(validator.schema_name(), "threatdb");
        assert_eq!(validator.database_type(), Some("ThreatDB-v1"));
    }

    #[test]
    fn test_unknown_schema() {
        let result = SchemaValidator::new("nonexistent");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, SchemaError::UnknownSchema(_, _)));
    }

    #[test]
    fn test_valid_threatdb_record() {
        let validator = SchemaValidator::new("threatdb").unwrap();
        let data = valid_threatdb_data();
        assert!(validator.validate(&data).is_ok());
    }

    #[test]
    fn test_valid_threatdb_with_optional_fields() {
        let validator = SchemaValidator::new("threatdb").unwrap();
        let mut data = valid_threatdb_data();
        data.insert("confidence".to_string(), DataValue::Uint32(85));
        data.insert(
            "description".to_string(),
            DataValue::String("Known malware C2".to_string()),
        );
        data.insert("tlp".to_string(), DataValue::String("AMBER".to_string()));
        assert!(validator.validate(&data).is_ok());
    }

    #[test]
    fn test_missing_required_field() {
        let validator = SchemaValidator::new("threatdb").unwrap();
        let mut data = HashMap::new();
        data.insert(
            "threat_level".to_string(),
            DataValue::String("high".to_string()),
        );
        // Missing category and source

        let result = validator.validate(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(!err.errors.is_empty());
        // Should mention missing required properties
        let error_text = format!("{}", err);
        assert!(
            error_text.contains("category") || error_text.contains("source"),
            "Error should mention missing field: {}",
            error_text
        );
    }

    #[test]
    fn test_invalid_enum_value() {
        let validator = SchemaValidator::new("threatdb").unwrap();
        let mut data = valid_threatdb_data();
        data.insert(
            "threat_level".to_string(),
            DataValue::String("super-critical".to_string()), // Not a valid enum value
        );

        let result = validator.validate(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let error_text = format!("{}", err);
        assert!(
            error_text.contains("threat_level") || error_text.contains("enum"),
            "Error should mention invalid enum: {}",
            error_text
        );
    }

    #[test]
    fn test_invalid_confidence_range() {
        let validator = SchemaValidator::new("threatdb").unwrap();
        let mut data = valid_threatdb_data();
        data.insert("confidence".to_string(), DataValue::Uint32(150)); // > 100

        let result = validator.validate(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let error_text = format!("{}", err);
        assert!(
            error_text.contains("confidence") || error_text.contains("maximum"),
            "Error should mention confidence range: {}",
            error_text
        );
    }

    #[test]
    fn test_invalid_tlp_value() {
        let validator = SchemaValidator::new("threatdb").unwrap();
        let mut data = valid_threatdb_data();
        data.insert(
            "tlp".to_string(),
            DataValue::String("purple".to_string()), // Not a valid TLP
        );

        let result = validator.validate(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_type_for_field() {
        let validator = SchemaValidator::new("threatdb").unwrap();
        let mut data = valid_threatdb_data();
        data.insert(
            "confidence".to_string(),
            DataValue::String("high".to_string()),
        ); // Should be integer

        let result = validator.validate(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_additional_properties_allowed() {
        let validator = SchemaValidator::new("threatdb").unwrap();
        let mut data = valid_threatdb_data();
        // Schema has additionalProperties: true
        data.insert(
            "custom_field".to_string(),
            DataValue::String("custom value".to_string()),
        );

        assert!(validator.validate(&data).is_ok());
    }

    #[test]
    fn test_tags_array() {
        let validator = SchemaValidator::new("threatdb").unwrap();
        let mut data = valid_threatdb_data();
        data.insert(
            "tags".to_string(),
            DataValue::Array(vec![
                DataValue::String("emotet".to_string()),
                DataValue::String("banking-trojan".to_string()),
            ]),
        );

        assert!(validator.validate(&data).is_ok());
    }

    #[test]
    fn test_validate_detailed() {
        let validator = SchemaValidator::new("threatdb").unwrap();
        let data = HashMap::new(); // Empty - missing all required fields

        let errors = validator.validate_detailed(&data);
        assert!(!errors.is_empty());
        // Should have errors for missing threat_level, category, source
    }

    #[test]
    fn test_error_display() {
        let err = SchemaValidationError {
            errors: vec![
                ValidationErrorDetail {
                    path: "/threat_level".to_string(),
                    message: "value must be one of: critical, high, medium, low, unknown"
                        .to_string(),
                },
                ValidationErrorDetail {
                    path: "/confidence".to_string(),
                    message: "value must be <= 100".to_string(),
                },
            ],
        };

        let display = format!("{}", err);
        assert!(display.contains("2 errors"));
        assert!(display.contains("threat_level"));
        assert!(display.contains("confidence"));
    }
}
