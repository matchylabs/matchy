//! MISP JSON Threat Intelligence Importer
//!
//! This module provides functionality to import threat intelligence data from MISP JSON files
//! into the paraglob database format. It supports various MISP attribute types including
//! IP addresses, domains, hashes, URLs, and more.
//!
//! # MISP Format
//!
//! MISP (Malware Information Sharing Platform) uses a JSON format to exchange threat
//! intelligence. This importer focuses on extracting actionable indicators from:
//! - Event-level attributes
//! - Object-embedded attributes  
//! - Tags and metadata
//!
//! # Supported Attribute Types
//!
//! ## Network Indicators
//! - `ip-src`, `ip-dst`, `ip`: IP addresses
//! - `ip-src/netmask`, `ip-dst/netmask`: IP subnets in CIDR notation
//! - `ip-src|port`, `ip-dst|port`: IP with port (IP extracted)
//! - `domain`, `hostname`: Domain names
//! - `domain|ip`: Domain with IP (both extracted)
//! - `url`: URLs (domain extracted)
//!
//! ## File Indicators
//! - `md5`, `sha1`, `sha256`, `sha384`, `sha512`: File hashes
//! - `sha3-*`, `ssdeep`, `imphash`, `tlsh`: Alternative hashes
//! - `filename`: Filenames (treated as patterns)
//! - `filename|*`: Combined filename and hash (both extracted)
//!
//! ## Email Indicators
//! - `email`, `email-src`, `email-dst`: Email addresses
//! - `email-subject`: Email subjects (pattern match)
//!
//! # Example
//!
//! ```rust,no_run
//! use matchy::misp_importer::MispImporter;
//! use matchy::MatchMode;
//! use std::fs;
//!
//! // Load MISP JSON file
//! let json_data = fs::read_to_string("threat_intel.json")?;
//!
//! // Parse and extract indicators
//! let importer = MispImporter::from_json(&json_data)?;
//!
//! // Build database
//! let database = importer.build_database(MatchMode::CaseSensitive)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::data_section::DataValue;
use crate::error::ParaglobError;
use crate::glob::MatchMode;
use crate::mmdb_builder::MmdbBuilder;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Custom deserializer for value field that accepts strings, numbers, booleans, and null
fn deserialize_value<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    use serde_json::Value;

    let value = Value::deserialize(deserializer)?;

    match value {
        Value::String(s) => Ok(s),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Null => Ok(String::new()), // Treat null as empty string
        Value::Array(_) | Value::Object(_) => Ok(String::new()), // Skip complex types
    }
}

/// Custom deserializer for u8 fields that accepts both strings and numbers
fn deserialize_u8_flexible<'de, D>(deserializer: D) -> Result<Option<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    use serde_json::Value;

    let value = Value::deserialize(deserializer)?;

    match value {
        Value::Number(n) => n
            .as_u64()
            .and_then(|n| u8::try_from(n).ok())
            .ok_or_else(|| Error::custom("number out of u8 range"))
            .map(Some),
        Value::String(s) => s
            .parse::<u8>()
            .map(Some)
            .map_err(|_| Error::custom("invalid u8 string")),
        Value::Null => Ok(None),
        _ => Err(Error::custom("expected number or string for u8")),
    }
}

/// Custom deserializer for u64 fields that accepts both strings and numbers
fn deserialize_u64_flexible<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    use serde_json::Value;

    let value = Value::deserialize(deserializer)?;

    match value {
        Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| Error::custom("number out of u64 range"))
            .map(Some),
        Value::String(s) => s
            .parse::<u64>()
            .map(Some)
            .map_err(|_| Error::custom("invalid u64 string")),
        Value::Null => Ok(None),
        _ => Err(Error::custom("expected number or string for u64")),
    }
}

/// MISP Event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispEvent {
    /// Event UUID
    #[serde(default)]
    pub uuid: Option<String>,

    /// Event info/description
    #[serde(default)]
    pub info: Option<String>,

    /// Threat level (1=High, 2=Medium, 3=Low, 4=Undefined)
    #[serde(default, deserialize_with = "deserialize_u8_flexible")]
    pub threat_level_id: Option<u8>,

    /// Analysis level (0=Initial, 1=Ongoing, 2=Complete)
    #[serde(default, deserialize_with = "deserialize_u8_flexible")]
    pub analysis: Option<u8>,

    /// Event date
    #[serde(default)]
    pub date: Option<String>,

    /// Unix timestamp
    #[serde(default, deserialize_with = "deserialize_u64_flexible")]
    pub timestamp: Option<u64>,

    /// Published flag
    #[serde(default)]
    pub published: Option<bool>,

    /// Organization that created the event
    #[serde(rename = "Orgc", default)]
    pub orgc: Option<MispOrg>,

    /// Event tags
    #[serde(rename = "Tag", default)]
    pub tags: Vec<MispTag>,

    /// Direct attributes
    #[serde(rename = "Attribute", default)]
    pub attributes: Vec<MispAttribute>,

    /// Object-grouped attributes
    #[serde(rename = "Object", default)]
    pub objects: Vec<MispObject>,
}

/// MISP Organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispOrg {
    /// Organization UUID
    #[serde(default)]
    pub uuid: Option<String>,
    /// Organization name
    #[serde(default)]
    pub name: Option<String>,
}

/// MISP Tag
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispTag {
    /// Tag name
    pub name: String,
    /// Tag color in hexadecimal format
    #[serde(default)]
    pub colour: Option<String>,
    /// Whether this tag can be exported
    #[serde(default)]
    pub exportable: Option<bool>,
}

/// MISP Attribute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispAttribute {
    /// Attribute UUID
    #[serde(default)]
    pub uuid: Option<String>,

    /// Attribute type (e.g., "ip-src", "md5", "domain")
    #[serde(rename = "type")]
    pub attribute_type: String,

    /// Attribute value (can be string or number)
    #[serde(deserialize_with = "deserialize_value")]
    pub value: String,

    /// Category
    #[serde(default)]
    pub category: Option<String>,

    /// To IDS flag (actionable indicator)
    #[serde(default)]
    pub to_ids: Option<bool>,

    /// Comment
    #[serde(default)]
    pub comment: Option<String>,

    /// Unix timestamp
    #[serde(default, deserialize_with = "deserialize_u64_flexible")]
    pub timestamp: Option<u64>,

    /// Object relation (if part of an object)
    #[serde(default)]
    pub object_relation: Option<String>,

    /// Attribute tags
    #[serde(rename = "Tag", default)]
    pub tags: Vec<MispTag>,
}

/// MISP Object (grouped attributes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispObject {
    /// Object UUID
    #[serde(default)]
    pub uuid: Option<String>,

    /// Object name/type (e.g., "file", "network-connection")
    pub name: String,

    /// Meta category
    #[serde(rename = "meta-category", default)]
    pub meta_category: Option<String>,

    /// Description
    #[serde(default)]
    pub description: Option<String>,

    /// Comment
    #[serde(default)]
    pub comment: Option<String>,

    /// Unix timestamp
    #[serde(default, deserialize_with = "deserialize_u64_flexible")]
    pub timestamp: Option<u64>,

    /// Attributes in this object
    #[serde(rename = "Attribute", default)]
    pub attributes: Vec<MispAttribute>,
}

/// Top-level MISP JSON wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispDocument {
    /// The MISP event contained in this document
    #[serde(rename = "Event")]
    pub event: MispEvent,
}

/// MISP Importer for building paraglob databases from MISP JSON
pub struct MispImporter {
    events: Vec<MispEvent>,
}

impl MispImporter {
    /// Create importer from MISP JSON string
    pub fn from_json(json: &str) -> Result<Self, ParaglobError> {
        let doc: MispDocument = serde_json::from_str(json).map_err(|e| {
            ParaglobError::InvalidPattern(format!("Failed to parse MISP JSON: {}", e))
        })?;

        Ok(Self {
            events: vec![doc.event],
        })
    }

    /// Build a database directly from files with streaming processing (low memory)
    ///
    /// This processes files one at a time without loading all events into memory,
    /// making it suitable for very large datasets. Files that don't contain valid
    /// MISP events (like manifest.json) are skipped with a warning.
    pub fn build_from_files<P: AsRef<Path>>(
        paths: &[P],
        match_mode: MatchMode,
        minimal_metadata: bool,
    ) -> Result<MmdbBuilder, ParaglobError> {
        let mut builder = MmdbBuilder::new(match_mode)
            .with_database_type("MISP-ThreatIntel")
            .with_description("en", "Threat intelligence database from MISP JSON feeds");

        let mut skipped_files = Vec::new();
        let mut processed_events = 0;

        for path in paths {
            let path_ref = path.as_ref();
            let json = fs::read_to_string(path_ref).map_err(|e| {
                ParaglobError::InvalidPattern(format!("Failed to read file: {}", e))
            })?;

            // Try to parse as MISP event document
            match serde_json::from_str::<MispDocument>(&json) {
                Ok(doc) => {
                    // Process event immediately and drop it
                    let temp_importer = Self {
                        events: vec![doc.event],
                    };

                    for event in &temp_importer.events {
                        if minimal_metadata {
                            temp_importer.process_event_minimal(event, &mut builder)?;
                        } else {
                            temp_importer.process_event(event, &mut builder)?;
                        }
                    }
                    processed_events += 1;
                    // Event is dropped here, freeing memory
                }
                Err(e) => {
                    // Check if it's a known non-event file
                    let filename = path_ref
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown");

                    if filename == "manifest.json" || filename == "hashes.csv" {
                        // Known metadata files - skip silently
                        skipped_files.push((filename.to_string(), "metadata file".to_string()));
                    } else if json.trim_start().starts_with('{') && json.contains("\"Event\"") {
                        // Looks like it should be a MISP file but failed to parse - this is an error
                        return Err(ParaglobError::InvalidPattern(format!(
                            "Failed to parse MISP JSON in {}: {}",
                            filename, e
                        )));
                    } else {
                        // Doesn't look like a MISP event file - skip with warning
                        skipped_files.push((filename.to_string(), "not a MISP event".to_string()));
                    }
                }
            }
        }

        // Print warnings for skipped files
        if !skipped_files.is_empty() {
            eprintln!("Warning: Skipped {} non-MISP file(s):", skipped_files.len());
            for (filename, reason) in &skipped_files {
                eprintln!("  - {}: {}", filename, reason);
            }
        }

        if processed_events == 0 {
            return Err(ParaglobError::InvalidPattern(
                "No valid MISP events found in provided files".to_string(),
            ));
        }

        Ok(builder)
    }

    /// Create importer from multiple MISP JSON files (loads all into memory)
    ///
    /// Files that don't contain valid MISP events (like manifest.json) are skipped with a warning.
    ///
    /// **Note:** For large datasets, use `build_from_files()` instead which streams
    /// files one at a time without loading everything into memory.
    pub fn from_files<P: AsRef<Path>>(paths: &[P]) -> Result<Self, ParaglobError> {
        let mut events = Vec::new();
        let mut skipped_files = Vec::new();

        for path in paths {
            let path_ref = path.as_ref();
            let json = fs::read_to_string(path_ref).map_err(|e| {
                ParaglobError::InvalidPattern(format!("Failed to read file: {}", e))
            })?;

            // Try to parse as MISP event document
            match serde_json::from_str::<MispDocument>(&json) {
                Ok(doc) => {
                    events.push(doc.event);
                }
                Err(e) => {
                    // Check if it's a known non-event file
                    let filename = path_ref
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown");

                    if filename == "manifest.json" || filename == "hashes.csv" {
                        // Known metadata files - skip silently
                        skipped_files.push((filename.to_string(), "metadata file".to_string()));
                    } else if json.trim_start().starts_with('{') && json.contains("\"Event\"") {
                        // Looks like it should be a MISP file but failed to parse - this is an error
                        return Err(ParaglobError::InvalidPattern(format!(
                            "Failed to parse MISP JSON in {}: {}",
                            filename, e
                        )));
                    } else {
                        // Doesn't look like a MISP event file - skip with warning
                        skipped_files.push((filename.to_string(), "not a MISP event".to_string()));
                    }
                }
            }
        }

        // Print warnings for skipped files
        if !skipped_files.is_empty() {
            eprintln!("Warning: Skipped {} non-MISP file(s):", skipped_files.len());
            for (filename, reason) in &skipped_files {
                eprintln!("  - {}: {}", filename, reason);
            }
        }

        if events.is_empty() {
            return Err(ParaglobError::InvalidPattern(
                "No valid MISP events found in provided files".to_string(),
            ));
        }

        Ok(Self { events })
    }

    /// Build a paraglob database from imported MISP data
    pub fn build_database(&self, match_mode: MatchMode) -> Result<MmdbBuilder, ParaglobError> {
        self.build_database_with_options(match_mode, false)
    }

    /// Build a paraglob database with minimal metadata for smaller size
    ///
    /// When `minimal_metadata` is true, only essential fields are stored:
    /// - type (attribute type)
    /// - threat_level
    /// - tags (combined)
    ///
    /// This can reduce database size by 50-70% for large feeds.
    pub fn build_database_with_options(
        &self,
        match_mode: MatchMode,
        minimal_metadata: bool,
    ) -> Result<MmdbBuilder, ParaglobError> {
        let mut builder = MmdbBuilder::new(match_mode)
            .with_database_type("MISP-ThreatIntel")
            .with_description("en", "Threat intelligence database from MISP JSON feeds");

        for event in &self.events {
            if minimal_metadata {
                self.process_event_minimal(event, &mut builder)?;
            } else {
                self.process_event(event, &mut builder)?;
            }
        }

        Ok(builder)
    }

    /// Process event with minimal metadata (just threat level and tags)
    fn process_event_minimal(
        &self,
        event: &MispEvent,
        builder: &mut MmdbBuilder,
    ) -> Result<(), ParaglobError> {
        // Build minimal event metadata
        let mut event_metadata = HashMap::new();

        if let Some(threat_level) = event.threat_level_id {
            let threat_name = match threat_level {
                1 => "High",
                2 => "Medium",
                3 => "Low",
                _ => "Undefined",
            };
            event_metadata.insert(
                "threat_level".to_string(),
                DataValue::String(threat_name.to_string()),
            );
        }

        // Collect event tags only
        if !event.tags.is_empty() {
            let tag_names: Vec<String> = event.tags.iter().map(|t| t.name.clone()).collect();
            event_metadata.insert("tags".to_string(), DataValue::String(tag_names.join(",")));
        }

        // Process direct attributes
        for attr in &event.attributes {
            let mut metadata = event_metadata.clone();
            metadata.insert(
                "type".to_string(),
                DataValue::String(attr.attribute_type.clone()),
            );

            // Add attribute tags if any
            if !attr.tags.is_empty() {
                let tag_names: Vec<String> = attr.tags.iter().map(|t| t.name.clone()).collect();
                let existing_tags = metadata
                    .get("tags")
                    .and_then(|v| {
                        if let DataValue::String(s) = v {
                            Some(s.as_str())
                        } else {
                            None
                        }
                    })
                    .unwrap_or("");

                let combined = if existing_tags.is_empty() {
                    tag_names.join(",")
                } else {
                    format!("{},{}", existing_tags, tag_names.join(","))
                };
                metadata.insert("tags".to_string(), DataValue::String(combined));
            }

            self.extract_indicators(&attr.attribute_type, &attr.value, metadata, builder)?;
        }

        // Process object-embedded attributes with minimal metadata
        for obj in &event.objects {
            for attr in &obj.attributes {
                let mut metadata = event_metadata.clone();
                metadata.insert(
                    "type".to_string(),
                    DataValue::String(attr.attribute_type.clone()),
                );

                // Add attribute tags
                if !attr.tags.is_empty() {
                    let tag_names: Vec<String> = attr.tags.iter().map(|t| t.name.clone()).collect();
                    let existing_tags = metadata
                        .get("tags")
                        .and_then(|v| {
                            if let DataValue::String(s) = v {
                                Some(s.as_str())
                            } else {
                                None
                            }
                        })
                        .unwrap_or("");

                    let combined = if existing_tags.is_empty() {
                        tag_names.join(",")
                    } else {
                        format!("{},{}", existing_tags, tag_names.join(","))
                    };
                    metadata.insert("tags".to_string(), DataValue::String(combined));
                }

                self.extract_indicators(&attr.attribute_type, &attr.value, metadata, builder)?;
            }
        }

        Ok(())
    }

    /// Process a single MISP event
    fn process_event(
        &self,
        event: &MispEvent,
        builder: &mut MmdbBuilder,
    ) -> Result<(), ParaglobError> {
        // Build event-level metadata
        let event_metadata = self.build_event_metadata(event);

        // Process direct attributes
        for attr in &event.attributes {
            self.process_attribute(attr, &event_metadata, builder)?;
        }

        // Process object-embedded attributes
        for obj in &event.objects {
            let mut obj_metadata = event_metadata.clone();

            // Add object metadata
            obj_metadata.insert(
                "object_type".to_string(),
                DataValue::String(obj.name.clone()),
            );
            if let Some(comment) = &obj.comment {
                obj_metadata.insert(
                    "object_comment".to_string(),
                    DataValue::String(comment.clone()),
                );
            }

            for attr in &obj.attributes {
                self.process_attribute(attr, &obj_metadata, builder)?;
            }
        }

        Ok(())
    }

    /// Build metadata from event
    fn build_event_metadata(&self, event: &MispEvent) -> HashMap<String, DataValue> {
        let mut metadata = HashMap::new();

        if let Some(info) = &event.info {
            metadata.insert("event_info".to_string(), DataValue::String(info.clone()));
        }

        if let Some(uuid) = &event.uuid {
            metadata.insert("event_uuid".to_string(), DataValue::String(uuid.clone()));
        }

        if let Some(threat_level) = event.threat_level_id {
            let threat_name = match threat_level {
                1 => "High",
                2 => "Medium",
                3 => "Low",
                _ => "Undefined",
            };
            metadata.insert(
                "threat_level".to_string(),
                DataValue::String(threat_name.to_string()),
            );
        }

        if let Some(analysis) = event.analysis {
            let analysis_name = match analysis {
                0 => "Initial",
                1 => "Ongoing",
                2 => "Complete",
                _ => "Unknown",
            };
            metadata.insert(
                "analysis".to_string(),
                DataValue::String(analysis_name.to_string()),
            );
        }

        if let Some(date) = &event.date {
            metadata.insert("event_date".to_string(), DataValue::String(date.clone()));
        }

        if let Some(orgc) = &event.orgc {
            if let Some(name) = &orgc.name {
                metadata.insert("org_name".to_string(), DataValue::String(name.clone()));
            }
        }

        // Collect tags
        if !event.tags.is_empty() {
            let tag_names: Vec<String> = event.tags.iter().map(|t| t.name.clone()).collect();
            metadata.insert("tags".to_string(), DataValue::String(tag_names.join(",")));
        }

        metadata
    }

    /// Process a single attribute and add to builder
    fn process_attribute(
        &self,
        attr: &MispAttribute,
        base_metadata: &HashMap<String, DataValue>,
        builder: &mut MmdbBuilder,
    ) -> Result<(), ParaglobError> {
        // Build metadata for this attribute
        let mut metadata = base_metadata.clone();

        metadata.insert(
            "type".to_string(),
            DataValue::String(attr.attribute_type.clone()),
        );

        if let Some(category) = &attr.category {
            metadata.insert("category".to_string(), DataValue::String(category.clone()));
        }

        if let Some(to_ids) = attr.to_ids {
            metadata.insert("to_ids".to_string(), DataValue::Bool(to_ids));
        }

        if let Some(comment) = &attr.comment {
            if !comment.is_empty() {
                metadata.insert("comment".to_string(), DataValue::String(comment.clone()));
            }
        }

        // Add attribute-specific tags
        if !attr.tags.is_empty() {
            let tag_names: Vec<String> = attr.tags.iter().map(|t| t.name.clone()).collect();
            let existing_tags = metadata
                .get("tags")
                .and_then(|v| {
                    if let DataValue::String(s) = v {
                        Some(s.as_str())
                    } else {
                        None
                    }
                })
                .unwrap_or("");

            let combined = if existing_tags.is_empty() {
                tag_names.join(",")
            } else {
                format!("{},{}", existing_tags, tag_names.join(","))
            };
            metadata.insert("tags".to_string(), DataValue::String(combined));
        }

        // Extract and add indicators based on type
        self.extract_indicators(&attr.attribute_type, &attr.value, metadata, builder)?;

        Ok(())
    }

    /// Extract indicators from attribute value based on type
    fn extract_indicators(
        &self,
        attr_type: &str,
        value: &str,
        metadata: HashMap<String, DataValue>,
        builder: &mut MmdbBuilder,
    ) -> Result<(), ParaglobError> {
        // Skip empty values (from null or missing data)
        if value.trim().is_empty() {
            return Ok(());
        }

        match attr_type {
            // IP addresses - use explicit add_ip() (also handles CIDR notation)
            "ip-src" | "ip-dst" | "ip" => {
                builder.add_ip(value, metadata)?;
            }

            // IP with netmask (CIDR blocks) - use explicit add_ip()
            "ip-src/netmask" | "ip-dst/netmask" => {
                // Value should be in CIDR notation like "192.168.1.0/24"
                builder.add_ip(value, metadata)?;
            }

            // IP with port - extract IP and use add_ip()
            "ip-src|port" | "ip-dst|port" => {
                if let Some(pipe_pos) = value.find('|') {
                    let ip = &value[..pipe_pos];
                    builder.add_ip(ip, metadata)?;
                }
            }

            // Domains - always literals
            "domain" | "hostname" => {
                builder.add_literal(value, metadata)?;
            }

            // Domain with IP - extract both, use appropriate methods
            "domain|ip" => {
                if let Some(pipe_pos) = value.find('|') {
                    let domain = &value[..pipe_pos];
                    let ip = &value[pipe_pos + 1..];

                    // Add domain as literal
                    builder.add_literal(domain, metadata.clone())?;
                    // Add IP using add_ip()
                    builder.add_ip(ip, metadata)?;
                }
            }

            // URLs - extract domain and URL as literals
            "url" | "uri" => {
                if let Some(domain) = self.extract_domain_from_url(value) {
                    builder.add_literal(domain, metadata.clone())?;
                }
                // Also add full URL as literal
                builder.add_literal(value, metadata)?;
            }

            // File hashes - always literals (including ssdeep with special chars)
            "md5" | "sha1" | "sha224" | "sha256" | "sha384" | "sha512" | "sha512/224"
            | "sha512/256" | "sha3-224" | "sha3-256" | "sha3-384" | "sha3-512" | "ssdeep"
            | "imphash" | "tlsh" | "authentihash" | "vhash" | "cdhash" | "pehash" | "impfuzzy"
            | "telfhash" => {
                builder.add_literal(value, metadata)?;
            }

            // Filename with hash - extract both as literals
            "filename|md5"
            | "filename|sha1"
            | "filename|sha256"
            | "filename|sha384"
            | "filename|sha512"
            | "filename|imphash"
            | "filename|ssdeep"
            | "filename|tlsh"
            | "filename|authentihash"
            | "filename|vhash"
            | "filename|pehash"
            | "filename|impfuzzy" => {
                if let Some(pipe_pos) = value.find('|') {
                    let filename = &value[..pipe_pos];
                    let hash = &value[pipe_pos + 1..];

                    // Add filename as literal
                    builder.add_literal(filename, metadata.clone())?;
                    // Add hash as literal
                    builder.add_literal(hash, metadata)?;
                }
            }

            // Filenames - literals (may contain glob-like chars but shouldn't be treated as globs)
            "filename" | "filename-pattern" => {
                builder.add_literal(value, metadata)?;
            }

            // Email addresses - literals
            "email" | "email-src" | "email-dst" | "email-reply-to" => {
                builder.add_literal(value, metadata)?;
            }

            // Email subjects - literals
            "email-subject" | "email-body" => {
                builder.add_literal(value, metadata)?;
            }

            // Network patterns - literals
            "user-agent" | "http-method" => {
                builder.add_literal(value, metadata)?;
            }

            // MAC addresses - literals
            "mac-address" | "mac-eui-64" => {
                builder.add_literal(value, metadata)?;
            }

            // AS numbers - literals
            "AS" => {
                builder.add_literal(value, metadata)?;
            }

            // Cryptocurrency addresses - literals
            "btc" | "xmr" | "dash" => {
                builder.add_literal(value, metadata)?;
            }

            // Detection rules - literals (not globs, despite possibly containing patterns)
            "yara" | "snort" | "sigma" | "pattern-in-file" | "pattern-in-traffic"
            | "pattern-in-memory" => {
                builder.add_literal(value, metadata)?;
            }

            // Mutex, named pipes, registry keys - literals
            "mutex" | "named pipe" | "regkey" | "regkey|value" => {
                builder.add_literal(value, metadata)?;
            }

            // Ignore non-actionable types
            "comment" | "text" | "other" | "link" | "datetime" | "size-in-bytes" | "counter"
            | "float" | "hex" | "port" | "attachment" | "malware-sample" => {
                // Skip these - not useful for matching
            }

            // Default: add as literal if it looks actionable
            _ => {
                if !value.is_empty() && value.len() < 1000 {
                    builder.add_literal(value, metadata)?;
                }
            }
        }

        Ok(())
    }

    /// Extract domain from URL
    fn extract_domain_from_url<'a>(&self, url: &'a str) -> Option<&'a str> {
        // Simple URL parsing
        let url = url.trim();

        // Remove protocol if present
        let without_protocol = if let Some(pos) = url.find("://") {
            &url[pos + 3..]
        } else {
            url
        };

        // Extract domain (before first / or ?)
        let domain_end = without_protocol
            .find('/')
            .or_else(|| without_protocol.find('?'))
            .or_else(|| without_protocol.find('#'))
            .unwrap_or(without_protocol.len());

        let domain = &without_protocol[..domain_end];

        // Remove port if present
        let domain = if let Some(colon_pos) = domain.rfind(':') {
            // Check if it's actually a port (numbers after colon)
            if domain[colon_pos + 1..].chars().all(|c| c.is_numeric()) {
                &domain[..colon_pos]
            } else {
                domain
            }
        } else {
            domain
        };

        if domain.is_empty() {
            None
        } else {
            Some(domain)
        }
    }

    /// Get statistics about the imported data
    pub fn stats(&self) -> ImportStats {
        let mut stats = ImportStats::default();

        for event in &self.events {
            stats.total_events += 1;
            stats.total_attributes += event.attributes.len();

            for obj in &event.objects {
                stats.total_objects += 1;
                stats.total_attributes += obj.attributes.len();
            }
        }

        stats
    }
}

/// Statistics about imported MISP data
#[derive(Debug, Default, Clone)]
pub struct ImportStats {
    /// Total number of MISP events imported
    pub total_events: usize,
    /// Total number of attributes across all events
    pub total_attributes: usize,
    /// Total number of MISP objects across all events
    pub total_objects: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain_from_url() {
        let importer = MispImporter { events: vec![] };

        assert_eq!(
            importer.extract_domain_from_url("http://example.com/path"),
            Some("example.com")
        );
        assert_eq!(
            importer.extract_domain_from_url("https://test.org:8080/"),
            Some("test.org")
        );
        assert_eq!(
            importer.extract_domain_from_url("example.net"),
            Some("example.net")
        );
        assert_eq!(
            importer.extract_domain_from_url("http://evil.com?param=value"),
            Some("evil.com")
        );
    }

    #[test]
    fn test_parse_misp_json() {
        let json = r#"{
            "Event": {
                "uuid": "test-uuid",
                "info": "Test Event",
                "threat_level_id": 2,
                "Attribute": [
                    {
                        "type": "ip-src",
                        "value": "192.168.1.1"
                    }
                ],
                "Object": []
            }
        }"#;

        let importer = MispImporter::from_json(json).unwrap();
        assert_eq!(importer.events.len(), 1);
        assert_eq!(importer.events[0].attributes.len(), 1);
    }
}
